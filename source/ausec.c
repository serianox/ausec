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

#define AUSEC_XATTR_NAME "user.integrity.ausec"
#define AUSEC_DEFAULT_CONFIGURATION_FILE "/etc/ausec.cfg"
#define AUSEC_DEFAULT_ROOT_DIRECTORY NULL

struct pattern_node_options
{
	bool device, inode, mode, uid, gid, size, time, content;
};

struct pattern_node
{
	signed depth;
	char * pattern;
	struct pattern_node * parent, * child, * sibbling, * next;
	struct pattern_node_options options;
};

static struct
{
	bool check;
	bool update;
	bool verbose;
	const char * configuration_file;
	const char * root_directory;
}
configuration =
{
	.check = false,
	.update = false,
	.verbose = false,
	.configuration_file = AUSEC_DEFAULT_CONFIGURATION_FILE,
	.root_directory = AUSEC_DEFAULT_ROOT_DIRECTORY,
};

static char * hmac_key = NULL;

HMAC_CTX hmac_context;

#define log_debug(...) \
	((configuration.verbose)? fprintf(stderr, __VA_ARGS__): 0)

#define log_verbose(...) \
	((configuration.verbose)? fprintf(stderr, __VA_ARGS__): 0)

#define log_message(...) \
	(fprintf(stdout, __VA_ARGS__))

#define log_warning(...) \
	(fprintf(stderr, __VA_ARGS__))

#define log_error(...) \
	(fprintf(stderr, __VA_ARGS__))

static void usage(const char * program)
{
	printf("\
Usage: %s [options] [configuration_file] [root_directory]\n\
	-k, --key=KEY   key to be used in the signature computation\n\
	-c, --check     check the files against theirs signatures\n\
	-u, --update    update the files' signatures\n\
", program);
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

	int option, option_index; while ((option = getopt_long(argc, argv, options, long_options, &option_index)) != -1)
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
					log_warning(_("HMAC key was already previously set\n"));

				hmac_key = optarg;
				break;
			case 'h':
				usage(0[argv]);
				exit(0);
			case '?':
			case ':':
				usage(0[argv]);
				exit(-1);
			case 0:
				if (strcmp("verbose", long_options[option_index].name) == 0)
					configuration.verbose = true;

				break;
		}
	}

	if ((argc - optind) > 0)
		configuration.configuration_file = (optind++)[argv];

	if ((argc - optind) > 0)
		configuration.root_directory = (optind++)[argv];

	if ((argc - optind) > 0)
	{
		usage(0[argv]);
		exit(-1);
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
	log_debug("pattern: %s, path: %s, result: ", pattern, path);

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
		log_debug("none\n");
		return glob_none;

	end_partial:
		log_debug("partial\n");
		return glob_partial;

	end_match:
		log_debug("match\n");
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
		log_error(_("could not read extended attribute of `%s': %s\n"), filename, strerror(errno));

	return NULL;
}

static void set_xattr(const char * filename, FILE * fd, char * value)
{
	if (fsetxattr(fileno(fd), AUSEC_XATTR_NAME, value, strlen(value), 0) == -1)
		log_error(_("could not set extended attribute of `%s': %s\n"), filename, strerror(errno));
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
		log_error(_("error while reading `%s': %s\n"), path, strerror(errno));
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
			log_message(_("no signature found!\n"));
		else if (strcmp(current_xattr_value, new_xattr_value))
			log_message(_("integrity mismatch!\n"));
	}

	if (configuration.update)
		set_xattr(path, file, new_xattr_value);
}

static void walk_directory_recursive(const char * path, DIR * directory, struct pattern_node * patterns)
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

		if (lstat(relative_path, &file_stat) != 0)
		{
			log_error(_("can't stat file or directory `%s': %s\n"), absolute_path, strerror(errno));
			continue;
		}

		if (S_ISDIR(file_stat.st_mode))
		{
			DIR * new_directory;
			if ((new_directory = opendir(relative_path)) == NULL)
			{
				log_error(_("error when opening directory `%s': %s\n"), absolute_path, strerror(errno));
				continue;
			}

			if (fstat(dirfd(new_directory), &second_file_stat) != 0)
			{
				log_error(_("can't stat directory `%s': %s\n"), absolute_path, strerror(errno));
				continue;
			}

			if (file_stat.st_dev != second_file_stat.st_dev || file_stat.st_ino != second_file_stat.st_ino)
			{
				log_error(_("TOCTOU detected on `%s'!\n"), absolute_path);
				exit(-1);
			}

			if (fchdir(dirfd(new_directory)) != 0)
			{
				log_error(_("can't change directory to `%s': %s\n"), absolute_path, strerror(errno));
				continue;
			}

			for (struct pattern_node * current_pattern = patterns; current_pattern != NULL; current_pattern = current_pattern->next)
			{
				if (do_glob(current_pattern->pattern, absolute_path) != glob_none)
				{
					walk_directory_recursive(absolute_path, new_directory, current_pattern);
					break;
				}
			}

			closedir(new_directory);

			if (fchdir(dirfd(directory)) != 0)
			{
				log_error(_("could not return to previous directory: %s\n"), strerror(errno));
				// can't do anything more if it happens, so it's time to panic
				exit(-1);
			}
		}
		else if (S_ISREG(file_stat.st_mode))
		{
			FILE * file = fopen(relative_path, "rb");

			if (!file)
			{
				log_error(_("can't open file `%s': %s\n"), absolute_path, strerror(errno));
				continue;
			}

			if (fstat(fileno(file), &second_file_stat) != 0)
			{
				log_error(_("can't stat file `%s': %s\n"), absolute_path, strerror(errno));
				continue;
			}

			if (file_stat.st_dev != second_file_stat.st_dev || file_stat.st_ino != second_file_stat.st_ino)
			{
				log_error(_("TOCTOU detected on `%s'!\n"), absolute_path);
				exit(-1);
			}

			for (struct pattern_node * current_pattern = patterns; current_pattern != NULL; current_pattern = current_pattern->next)
			{
				if (do_glob(current_pattern->pattern, absolute_path) == glob_match)
				{
					audit_file(absolute_path, file, file_stat);
					break;
				}
			}

			fclose(file);
		}
		else if (S_ISLNK(file_stat.st_mode))
		{
		}

		free(absolute_path);
	}

	if (errno != 0)
		log_error(_("error while walking directory `%s': %s\n"), path, strerror(errno));
}

static void walk_directory(const char * path, struct pattern_node * patterns)
{
	DIR * starting_directory;
	if ((starting_directory = opendir((path == AUSEC_DEFAULT_ROOT_DIRECTORY)? "/": path)) == NULL)
	{
		log_error(_("error when opening directory `%s': %s"), path, strerror(errno));
		return;
	}

	if (fchdir(dirfd(starting_directory)) != 0)
	{
		log_error(_("can't change directory to `%s': %s\n"), path, strerror(errno));
		return;
	}

	walk_directory_recursive(((path == AUSEC_DEFAULT_ROOT_DIRECTORY)? "": path), starting_directory, patterns);

	closedir(starting_directory);
}

static void cleanup(void)
{
	HMAC_CTX_cleanup(&hmac_context);
}

static struct pattern_node * transform_pattern_tree(struct pattern_node * root_node)
{
	struct pattern_node * start_node, * current_node = root_node;

	for (; current_node->child != NULL; current_node = current_node->child);

	start_node = current_node;

	walking : while (true)
	{
		if (current_node->child != NULL)
		{
			current_node = current_node->child;
			continue;
		}

		if (current_node->sibbling != NULL)
		{
			current_node->next = current_node->sibbling;
			current_node = current_node->next;
			continue;
		}

		while (current_node->parent != root_node)
		{
			current_node->next = current_node->parent;
			current_node = current_node->next;

			if (current_node->sibbling != NULL)
			{
				current_node->next = current_node->sibbling;
				current_node = current_node->next;
				goto walking;
			}
		}

		break;
	}

	return start_node;
}

static struct pattern_node * parse_config(const char * config, const size_t config_size)
{
	const char * config_end = config + config_size;

	const char * path_begin, * path_end;
	char delimiter;
	signed depth;
	char * pattern;
	struct pattern_node * current_node = (struct pattern_node *) calloc(1, sizeof(struct pattern_node)), * root_node = current_node, * new_node;

	current_node->depth = -1;
	current_node->pattern = "";
	current_node->parent = current_node;
	current_node->options.size = true;
	current_node->options.content = true;

	goto start;

	new_line:
		if (++config == config_end)
			goto end;

	start:
		new_node = (struct pattern_node *) calloc(1, sizeof(struct pattern_node));
		depth = 0;
		goto indent;

	tab:
		++depth;
		if (++config == config_end)
			goto end;

	indent:
		if (*config == '\t')
			goto tab;
		new_node->depth = depth;
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

		pattern = (char *) calloc(1, path_end - path_begin + 1);
		memcpy(pattern, path_begin, path_end - path_begin);
		new_node->pattern = pattern;

		if (++config == config_end)
			goto error_partial;

		while (current_node->depth > depth)
			current_node = current_node->parent;

		if (current_node->depth == depth)
		{
			current_node->sibbling = new_node;
			new_node->parent = current_node->parent;
		}
		else if (current_node->depth + 1 == depth)
		{
			current_node->child = new_node;
			new_node->parent = current_node;
		}
		else
			goto error_depth;

		pattern = (char *) calloc(1, strlen(new_node->pattern) + strlen(new_node->parent->pattern) + 1);
		strcat(pattern, new_node->parent->pattern);
		strcat(pattern, new_node->pattern);
		free(new_node->pattern);
		new_node->pattern = pattern;

		memcpy(&(new_node->options), &(new_node->parent->options), sizeof(struct pattern_node_options));

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
		current_node = new_node;
		goto new_line;

	error_option:
	error_partial:
	error_depth:
		log_error("error while reading configuration (and too lazy to give a precise diagnostic)\n");
		return NULL;

	end:
		return transform_pattern_tree(root_node);
}

static void read_config(const char * config_path)
{
	FILE * config_file; if ((config_file = fopen(config_path, "rb")) == NULL)
	{
		log_error(_("can't open file `%s': %s\n"), config_path, strerror(errno));
		return;
	}

	struct stat config_stat; if (fstat(fileno(config_file), &config_stat) != 0)
	{
		log_error(_("can't stat file `%s': %s\n"), config_path, strerror(errno));
		return;
	}

	// empty file will cause mmap to fail allocation :(
	if (config_stat.st_size == 0)
		goto close;

	const char * config; if ((config = mmap(NULL, config_stat.st_size, PROT_READ, MAP_SHARED, fileno(config_file), 0)) == MAP_FAILED)
	{
		log_error(_("can't mmap file `%s': %s\n"), config_path, strerror(errno));
		return;
	}

	struct pattern_node * patterns; if ((patterns = parse_config(config, config_stat.st_size)) != NULL)
		walk_directory(configuration.root_directory, patterns);

	munmap((void *) config, config_stat.st_size);

	close:
		fclose(config_file);
}

int main(int argc, char * argv[])
{
	ENGINE_load_builtin_engines();
	ENGINE_register_all_complete();

	HMAC_CTX_init(&hmac_context);

	atexit(&cleanup);

	parse_arguments(argc, argv);

	read_config(configuration.configuration_file);
}
