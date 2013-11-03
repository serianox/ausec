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

static const char * AUSEC_XATTR_NAME = "user.integrity.ausec";

static bool check = false, update = false;

static void parse_arguments(int argc, char * argv[])
{
	// http://www.ibm.com/developerworks/aix/library/au-unix-getopt.html
	static const char * options = "cu";

	static const struct option long_options[] =
	{
		//{"verbose", no_argument, NULL, -'v'},
		//{"version", no_argument, NULL, 'v'},
		//{"help", no_argument, NULL, 'h'},
		{"check", no_argument, NULL, 'c'},
		{"update", no_argument, NULL, 'u'},
		{NULL, no_argument, NULL, 0}
	};

	int option = getopt_long(argc, argv, options, long_options, NULL);
	while (option != -1)
	{
		switch (option)
		{
			case 'c':
				check = true;
				break;
			case 'u':
				update = true;
				break;
			case 'h':
				// TODO
				break;
			case '?':
				// TODO
				break;
			case ':':
				// TODO
				break;
			case 0:
				// TODO
				break;
		}
		option = getopt_long(argc, argv, options, long_options, NULL);
	}
}

static char * get_xattr(FILE * fd)
{
	ssize_t buffer_size = fgetxattr(fileno(fd), AUSEC_XATTR_NAME, NULL, 0);

	if (buffer_size == -1)
		// don't perform diagnosis here
		goto read_failure;

	char * buffer = (char *)malloc(buffer_size + 1);

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

	EVP_MD_CTX digest_ctx;

	EVP_MD_CTX_init(&digest_ctx);
	EVP_DigestInit_ex(&digest_ctx, EVP_get_digestbyname("SHA1"), NULL);

	uint8_t input_buffer[4096];
	size_t read_size;

	while ((read_size = fread(input_buffer, 1, sizeof input_buffer, file)) != 0)
		EVP_DigestUpdate(&digest_ctx, input_buffer, read_size);

	if (ferror(file))
	{
		fprintf(stderr, "error while reading `%s': %s\n", path, strerror(errno));
		return;
	}

	uint8_t digest[EVP_MAX_MD_SIZE];
	unsigned digest_length;

	EVP_DigestFinal_ex(&digest_ctx, digest, &digest_length);
	EVP_MD_CTX_cleanup(&digest_ctx);

	char * new_xattr_value = (char *) malloc(digest_length * 2 + 1);
	for (unsigned i = 0; i < digest_length; ++i)
		sprintf(&(i * 2)[new_xattr_value], "%02x", i[digest]);
	new_xattr_value[digest_length * 2] = '\0';

	if (check && current_xattr_value != NULL && strcmp(current_xattr_value, new_xattr_value))
		fprintf(stdout, "integrity mismatch!\n");

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
			fprintf(stderr, "can't stat file or directory `%s': %s", absolute_path, strerror(errno));
			continue;
		}

		if (S_ISDIR(file_stat.st_mode))
		{
			DIR * new_directory;
			if ((new_directory = opendir(relative_path)) == NULL)
			{
				fprintf(stderr, "error when opening directory `%s': %s", absolute_path, strerror(errno));
				continue;
			}

			if (chdir(relative_path) != 0)
			{
				fprintf(stderr, "can't change directory to `%s': %s", absolute_path, strerror(errno));
				continue;
			}

			walk_directory_recursive(absolute_path, new_directory);

			closedir(new_directory);

			if (fchdir(dirfd(directory)) != 0)
			{
				fprintf(stderr, "could not return to previous directory: %s", strerror(errno));
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

	walk_directory_recursive(path, starting_directory);

	closedir(starting_directory);
}

static void init()
{
	OpenSSL_add_all_digests();
}

int main(int argc, char * argv[])
{
	init();

	parse_arguments(argc, argv);

	walk_directory(".");
}
