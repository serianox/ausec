/*
 *	Copyright 2013 Thomas Duboucher <thomas at duboucher dot eu>
 *
 *	This software is governed by the CeCILL-B license under French law and
 *	abiding by the rules of distribution of free software.  You can  use,
 *	modify and/ or redistribute the software under the terms of the CeCILL-B
 *	license as circulated by CEA, CNRS and INRIA at the following URL
 *	"http://www.cecill.info".
 *
 *	As a counterpart to the access to the source code and  rights to copy,
 *	modify and redistribute granted by the license, users are provided only
 *	with a limited warranty  and the software's author,  the holder of the
 *	economic rights,  and the successive licensors  have only  limited
 *	liability.
 *
 *	In this respect, the user's attention is drawn to the risks associated
 *	with loading,  using,  modifying and/or developing or reproducing the
 *	software by the user in light of its specific status of free software,
 *	that may mean  that it is complicated to manipulate,  and  that  also
 *	therefore means  that it is reserved for developers  and  experienced
 *	professionals having in-depth computer knowledge. Users are therefore
 *	encouraged to load and test the software's suitability as regards their
 *	requirements in conditions enabling the security of their systems and/or
 *	data to be ensured and,  more generally, to use and operate it in the
 *	same conditions as regards security.
 *
 *	The fact that you are presently reading this means that you have had
 *	knowledge of the CeCILL-B license and that you accept its terms.
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <unistd.h>
#include <getopt.h>
#include <libintl.h>
#include <locale.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <attr/xattr.h>

#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/hmac.h>

#define _(STRING) gettext(STRING)

static const char * AUSEC_XATTR_NAME = "user.integrity.ausec";

static struct
{
	bool check;
	bool update;
	bool verbose;
}
configuration =
{
	.check = false,
	.update = false,
	.verbose = false,
};

static char * hmac_key = NULL;

HMAC_CTX hmac_context;

static void usage(const char * program)
{
	printf("\
Usage: %s [OPTION]\n\
	-k, --key=KEY   key to be used in the signature computation\n\
	-c, --check     check the files against theirs signatures\n\
	-u, --update    update the files' signatures\n\
", program);
	exit(0);
}

static void parse_arguments(int argc, char * argv[])
{
	// http://www.ibm.com/developerworks/aix/library/au-unix-getopt.html
	static const char * options = "cuk:";

	static const struct option long_options[] =
	{
		{"verbose", no_argument, NULL, 0},
		//{"version", no_argument, NULL, 'v'},
		{"help", no_argument, NULL, 'h'},
		{"check", no_argument, NULL, 'c'},
		{"update", no_argument, NULL, 'u'},
		{"key", required_argument, NULL, 'k'},
		{NULL, no_argument, NULL, 0}
	};

	int option, option_index;
	while ((option = getopt_long(argc, argv, options, long_options, &option_index)) != -1)
	{
		switch (option)
		{
			case 'c':
				configuration.check = true;
				break;
			case 'u':
				configuration.update = true;
				break;
			case 'k':
				if (hmac_key != NULL)
					fprintf(stderr, _("HMAC key was already previously set\n"));

				hmac_key = optarg;
				break;
			case 'h':
			case '?':
			case ':':
				usage(0[argv]);
			case 0:
				if (strcmp("verbose", long_options[option_index].name) == 0)
					configuration.verbose = true;

				break;
		}
	}

	if (!configuration.check && !configuration.update)
	{
		// nothing to do...
		exit(0);
	}

	if (hmac_key == NULL)
		hmac_key = "";

	HMAC_Init_ex(&hmac_context, hmac_key, strlen(hmac_key), EVP_sha256(), NULL);
}

const int glob_match = 0, glob_none = -1, glob_partial = 1;

static int do_glob(const char * pattern, const char * path)
{
	const char * pattern_end = pattern + strlen(pattern);
	const char * path_end = path + strlen(path);

	goto start;

	next_pattern:
		if (++pattern == pattern_end)
			goto end_match;
	next:
		if (++path == path_end)
			goto end_partial;

	start:
		if (*pattern == '?')
			goto match_eroteme;
		if (*pattern == '*')
			goto match_star;
		goto match_default;

	match_default:
		if (*pattern != *path)
			goto error;
		goto next_pattern;

	match_eroteme:
		if (*path == '/')
			goto error;
		goto next_pattern;

	match_star:
		if (++pattern != pattern_end)
			goto match_star_lookahead;
		goto match_star_tail;

	match_star_tail:
		if (*path == '/')
			goto end_partial;
		if (++path != path_end)
			goto end_match;
		goto match_star_tail;

	match_star_lookahead:
		if (*path == *pattern)
			goto next_pattern;
		if (*path == '/')
			goto next;
		if (++path == path_end)
			goto end_none;
		goto match_star_lookahead;

	error:
	end_none:
		return glob_none;

	end_partial:
		return glob_partial;

	end_match:
		return glob_match;
}

static char * get_xattr(const char * filename, FILE * fd)
{
	ssize_t buffer_size = fgetxattr(fileno(fd), AUSEC_XATTR_NAME, NULL, 0);

	if (buffer_size == -1)
		// don't perform diagnosis here
		goto read_failure;

	char * buffer = (char *) malloc(buffer_size + 1);

	if (fgetxattr(fileno(fd), AUSEC_XATTR_NAME, buffer, buffer_size) == -1)
	{
		free(buffer);

		goto read_failure;
	}

	buffer[buffer_size] = '\0';

	return buffer;

	read_failure:
		fprintf(stderr, _("could not read extended attribute of `%s': %s\n"), filename, strerror(errno));

	return NULL;
}

static void set_xattr(const char * filename, FILE * fd, char * value)
{
	if (fsetxattr(fileno(fd), AUSEC_XATTR_NAME, value, strlen(value), 0) == -1)
		fprintf(stderr, _("could not set extended attribute of `%s': %s\n"), filename, strerror(errno));
}

static void audit_file(const char * path, FILE * file, struct stat file_stat)
{
	char * current_xattr_value = get_xattr(path, file);

	HMAC_Init_ex(&hmac_context, NULL, 0, NULL, NULL);

	HMAC_Update(&hmac_context, (const unsigned char *) &file_stat.st_dev, sizeof file_stat.st_dev);
	HMAC_Update(&hmac_context, (const unsigned char *) &file_stat.st_ino, sizeof file_stat.st_ino);
	HMAC_Update(&hmac_context, (const unsigned char *) &file_stat.st_mode, sizeof file_stat.st_mode);
	HMAC_Update(&hmac_context, (const unsigned char *) &file_stat.st_uid, sizeof file_stat.st_uid);
	HMAC_Update(&hmac_context, (const unsigned char *) &file_stat.st_gid, sizeof file_stat.st_gid);
	HMAC_Update(&hmac_context, (const unsigned char *) &file_stat.st_size, sizeof file_stat.st_size);
	HMAC_Update(&hmac_context, (const unsigned char *) &file_stat.st_mtime, sizeof file_stat.st_mtime);
	HMAC_Update(&hmac_context, (const unsigned char *) &file_stat.st_ctime, sizeof file_stat.st_ctime);

	// playing with memory^Wmatches
	uint8_t input_buffer[file_stat.st_blksize];
	size_t read_size;

	while ((read_size = fread(input_buffer, 1, file_stat.st_blksize, file)) != 0)
		HMAC_Update(&hmac_context, input_buffer, read_size);

	if (ferror(file))
	{
		fprintf(stderr, _("error while reading `%s': %s\n"), path, strerror(errno));
		return;
	}

	uint8_t digest[EVP_MAX_MD_SIZE];
	unsigned digest_length;

	HMAC_Final(&hmac_context, digest, &digest_length);

	char * new_xattr_value = (char *) malloc(digest_length * 2 + 1);
	for (unsigned i = 0; i < digest_length; ++i)
		sprintf(&(i * 2)[new_xattr_value], "%02x", i[digest]);
	new_xattr_value[digest_length * 2] = '\0';

	if (configuration.check)
	{
		if (current_xattr_value == NULL)
			fprintf(stdout, _("no signature found!\n"));
		else if (strcmp(current_xattr_value, new_xattr_value))
			fprintf(stdout, _("integrity mismatch!\n"));
	}

	if (configuration.update)
		set_xattr(path, file, new_xattr_value);
}

static void walk_directory_recursive(const char * path, DIR * directory, const char * pattern)
{
	struct dirent * directory_entry;
	struct stat file_stat, second_file_stat;

	while ((errno = 0, directory_entry = readdir(directory)) != NULL)
	{
		if (!strcmp(directory_entry->d_name, ".") || !strcmp(directory_entry->d_name, ".."))
			continue;

		char * relative_path = directory_entry->d_name;
		char * absolute_path = (char *) malloc(snprintf(NULL, 0, "%s/%s", path, relative_path) + 1);
		sprintf(absolute_path, "%s/%s", path, relative_path);
		//printf("%s\n", absolute_path); // DEBUG

		if (lstat(relative_path, &file_stat) != 0)
		{
			fprintf(stderr, _("can't stat file or directory `%s': %s\n"), absolute_path, strerror(errno));
			continue;
		}

		if (S_ISDIR(file_stat.st_mode))
		{
			DIR * new_directory;
			if ((new_directory = opendir(relative_path)) == NULL)
			{
				fprintf(stderr, _("error when opening directory `%s': %s\n"), absolute_path, strerror(errno));
				continue;
			}

			if (fstat(dirfd(new_directory), &second_file_stat) != 0)
			{
				fprintf(stderr, _("can't stat directory `%s': %s\n"), absolute_path, strerror(errno));
				continue;
			}

			if (file_stat.st_dev != second_file_stat.st_dev || file_stat.st_ino != second_file_stat.st_ino)
			{
				fprintf(stderr, _("TOCTOU detected on `%s'!\n"), absolute_path);
				exit(-1);
			}

			if (fchdir(dirfd(new_directory)) != 0)
			{
				fprintf(stderr, _("can't change directory to `%s': %s\n"), absolute_path, strerror(errno));
				continue;
			}

			if (do_glob(pattern, absolute_path) != glob_none)
				walk_directory_recursive(absolute_path, new_directory, pattern);

			closedir(new_directory);

			if (fchdir(dirfd(directory)) != 0)
			{
				fprintf(stderr, _("could not return to previous directory: %s\n"), strerror(errno));
				// can't do anything more if it happens, so it's time to panic
				exit(-1);
			}
		}
		else if (S_ISREG(file_stat.st_mode))
		{
			FILE * file = fopen(relative_path, "rb");

			if (!file)
			{
				fprintf(stderr, _("can't open file `%s': %s\n"), absolute_path, strerror(errno));
				continue;
			}

			if (fstat(fileno(file), &second_file_stat) != 0)
			{
				fprintf(stderr, _("can't stat file `%s': %s\n"), absolute_path, strerror(errno));
				continue;
			}

			if (file_stat.st_dev != second_file_stat.st_dev || file_stat.st_ino != second_file_stat.st_ino)
			{
				fprintf(stderr, _("TOCTOU detected on `%s'!\n"), absolute_path);
				exit(-1);
			}

			if (do_glob(pattern, absolute_path) == glob_match)
				audit_file(absolute_path, file, file_stat);

			fclose(file);
		}
		else if (S_ISLNK(file_stat.st_mode))
		{
		}

		free(absolute_path);
	}

	if (errno != 0)
		fprintf(stderr, _("error while walking directory `%s': %s\n"), path, strerror(errno));
}

static void walk_directory(const char * path, const char * pattern)
{
	DIR * starting_directory;
	if ((starting_directory = opendir(path)) == NULL)
	{
		fprintf(stderr, _("error when opening directory `%s': %s"), path, strerror(errno));
		return;
	}

	if (fchdir(dirfd(starting_directory)) != 0)
	{
		fprintf(stderr, _("can't change directory to `%s': %s\n"), path, strerror(errno));
		return;
	}

	walk_directory_recursive(path, starting_directory, pattern);

	closedir(starting_directory);
}

static void cleanup(void)
{
	HMAC_CTX_cleanup(&hmac_context);
}

static void parse_config(const char * config, const size_t config_size)
{
	const char * config_end = config + config_size;

	const char * path_begin, * path_end;
	char delimiter, * path_;
	unsigned tabs;

	goto start;

	new_line:
		if (++config == config_end)
			goto end;

	start:
		tabs = 0;
		goto indent;

	tab:
		++tabs;
		if (++config == config_end)
			goto end;

	indent:
		if (*config == '\t')
			goto tab;
		delimiter = *config;
		if (++config == config_end)
			goto error_partial;
		path_begin = config;
		goto path;

	path_next:
		if (++config == config_end)
			goto error_partial;

	path:
		if (*config != delimiter)
			goto path_next;

		path_end = config;
		if (++config == config_end)
			goto error_partial;

	options:
		if (*config == '\n')
			goto finish_line;
		if (*config == '+')
			goto add_option;
		if (*config == '-')
			goto remove_option;
		goto error_option;

	add_option:
	remove_option:
		goto options;

	finish_line:
		path_ = (char *) malloc(path_end - path_begin);
		memcpy(path_, path_begin, path_end - path_begin);
		printf("%s\n", path_);
		goto new_line;

	error_option:
	error_partial:
		return;

	end:
		return;
}

static void read_config(const char * config_path)
{
	FILE * config_file; if ((config_file = fopen(config_path, "rb")) == NULL)
	{
		fprintf(stderr, _("can't open file `%s': %s\n"), config_path, strerror(errno));
		return;
	}

	struct stat config_stat; if (fstat(fileno(config_file), &config_stat) != 0)
	{
		fprintf(stderr, _("can't stat file `%s': %s\n"), config_path, strerror(errno));
		return;
	}

	// empty file will cause mmap to fail allocation :(
	if (config_stat.st_size == 0)
		goto close;

	const char * config; if ((config = mmap(NULL, config_stat.st_size, PROT_READ, MAP_SHARED, fileno(config_file), 0)) == MAP_FAILED)
	{
		fprintf(stderr, _("can't mmap file `%s': %s\n"), config_path, strerror(errno));
		return;
	}

	parse_config(config, config_stat.st_size);

	munmap((void *) config, config_stat.st_size);

	close:
		fclose(config_file);
}

static void init(int argc, char * argv[])
{
	read_config("./etc/ausec.cfg");

	ENGINE_load_builtin_engines();
	ENGINE_register_all_complete();

	HMAC_CTX_init(&hmac_context);

	atexit(&cleanup);

	parse_arguments(argc, argv);
}

int main(int argc, char * argv[])
{
	init(argc, argv);

	walk_directory(".", "./test/" "*");

	cleanup();
}
