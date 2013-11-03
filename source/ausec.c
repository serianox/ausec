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

#include <sys/types.h>
#include <sys/stat.h>

#include <attr/xattr.h>

#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/hmac.h>

static const char * AUSEC_XATTR_NAME = "user.integrity.ausec";

static bool check = false, update = false;

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
		//{"verbose", no_argument, NULL, -'v'},
		//{"version", no_argument, NULL, 'v'},
		//{"help", no_argument, NULL, 'h'},
		{"check", no_argument, NULL, 'c'},
		{"update", no_argument, NULL, 'u'},
		{"key", required_argument, NULL, 'k'},
		{NULL, no_argument, NULL, 0}
	};

	int option;
	while ((option = getopt_long(argc, argv, options, long_options, NULL)) != -1)
	{
		switch (option)
		{
			case 'c':
				check = true;
				break;
			case 'u':
				update = true;
				break;
			case 'k':
				if (hmac_key != NULL)
					fprintf(stderr, "HMAC key was already previously set\n");
				hmac_key = optarg;
				break;
			case 'h':
			case '?':
			case ':':
				usage(0[argv]);
			case 0:
				// TODO
				break;
		}
	}

	if (!check && !update)
	{
		// nothing to do...
		exit(0);
	}

	if (hmac_key == NULL)
		hmac_key = "";

	HMAC_Init_ex(&hmac_context, hmac_key, strlen(hmac_key), EVP_sha256(), NULL);
}

static char * get_xattr(FILE * fd)
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
		fprintf(stderr, "could not read attribute: %s\n", strerror(errno));

	return NULL;
}

static void set_xattr(FILE * fd, char * value)
{
	if (fsetxattr(fileno(fd), AUSEC_XATTR_NAME, value, strlen(value), 0) == -1)
		fprintf(stderr, "could not set attribute: %s\n", strerror(errno));
}

static void audit_file(const char * path, FILE * file)
{
	char * current_xattr_value = get_xattr(file);

	HMAC_Init_ex(&hmac_context, NULL, 0, NULL, NULL);

	fseek(file, 0L, SEEK_END);

	long file_length = ftell(file);
	HMAC_Update(&hmac_context, (const unsigned char *) &file_length, sizeof file_length);

	fseek(file, 0L, SEEK_SET);

	uint8_t input_buffer[4096];
	size_t read_size;

	while ((read_size = fread(input_buffer, 1, sizeof input_buffer, file)) != 0)
		HMAC_Update(&hmac_context, input_buffer, read_size);

	if (ferror(file))
	{
		fprintf(stderr, "error while reading `%s': %s\n", path, strerror(errno));
		return;
	}

	uint8_t digest[EVP_MAX_MD_SIZE];
	unsigned digest_length;

	HMAC_Final(&hmac_context, digest, &digest_length);

	char * new_xattr_value = (char *) malloc(digest_length * 2 + 1);
	for (unsigned i = 0; i < digest_length; ++i)
		sprintf(&(i * 2)[new_xattr_value], "%02x", i[digest]);
	new_xattr_value[digest_length * 2] = '\0';

	if (check)
	{
		if (current_xattr_value == NULL)
			fprintf(stdout, "no signature found!\n");
		else if (strcmp(current_xattr_value, new_xattr_value))
			fprintf(stdout, "integrity mismatch!\n");
	}

	if (update)
		set_xattr(file, new_xattr_value);
}

static void walk_directory_recursive(const char * path, DIR * directory)
{
	struct dirent * directory_entry;
	struct stat file_stat;

	while ((errno = 0, directory_entry = readdir(directory)) != NULL)
	{
		if (!strcmp(directory_entry->d_name, ".") || !strcmp(directory_entry->d_name, ".."))
			continue;

		char * relative_path = directory_entry->d_name;
		char * absolute_path = (char *) malloc(snprintf(NULL, 0, "%s/%s", path, relative_path) + 1);
		sprintf(absolute_path, "%s/%s", path, relative_path);
		printf("%s\n", absolute_path); // DEBUG

		if (lstat(relative_path, &file_stat) != 0)
		{
			fprintf(stderr, "can't stat file or directory `%s': %s\n", absolute_path, strerror(errno));
			continue;
		}

		if (S_ISDIR(file_stat.st_mode))
		{
			DIR * new_directory;
			if ((new_directory = opendir(relative_path)) == NULL)
			{
				fprintf(stderr, "error when opening directory `%s': %s\n", absolute_path, strerror(errno));
				continue;
			}

			if (fchdir(dirfd(new_directory)) != 0)
			{
				fprintf(stderr, "can't change directory to `%s': %s\n", absolute_path, strerror(errno));
				continue;
			}

			walk_directory_recursive(absolute_path, new_directory);

			closedir(new_directory);

			if (fchdir(dirfd(directory)) != 0)
			{
				fprintf(stderr, "could not return to previous directory: %s\n", strerror(errno));
				// can't do anything more if it happens, so it's time to panic
				exit(-1);
			}
		}
		else if (S_ISREG(file_stat.st_mode))
		{
			FILE * file = fopen(relative_path, "rb");

			if (!file)
				fprintf(stderr, "can't open `%s': %s\n", absolute_path, strerror(errno));

			audit_file(absolute_path, file);

			fclose(file);
		}
		else if (S_ISLNK(file_stat.st_mode))
		{
		}

		free(absolute_path);
	}

	if (errno != 0)
		fprintf(stderr, "error while walking directory `%s': %s\n", path, strerror(errno));
}

static void walk_directory(const char * path)
{
	DIR * starting_directory;
	if ((starting_directory = opendir(path)) == NULL)
	{
		fprintf(stderr, "error when opening directory `%s': %s", path, strerror(errno));
		return;
	}

	if (fchdir(dirfd(starting_directory)) != 0)
	{
		fprintf(stderr, "can't change directory to `%s': %s\n", path, strerror(errno));
		return;
	}

	walk_directory_recursive(path, starting_directory);

	closedir(starting_directory);
}

static void cleanup(void)
{
	HMAC_CTX_cleanup(&hmac_context);
}

static void init(void)
{
	ENGINE_load_builtin_engines();
	ENGINE_register_all_complete();

	HMAC_CTX_init(&hmac_context);

	atexit(&cleanup);
}

int main(int argc, char * argv[])
{
	init();

	parse_arguments(argc, argv);

	walk_directory(".");

	cleanup();
}
