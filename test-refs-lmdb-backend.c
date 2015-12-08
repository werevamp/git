#include "cache.h"
#include "string-list.h"
#include "parse-options.h"
#include "refs.h"

static const char * const test_refs_be_lmdb_usage[] = {
	"git test-refs-lmdb-backend <key>",
	"git test-refs-lmdb-backend <key> <value>",
	NULL,
};

int test_refdb_raw_read(const char *key);
void test_refdb_raw_write(const char *key, const char *value);
int test_refdb_raw_reflog(const char *refname);
int test_refdb_raw_delete(const char *key);
void test_refdb_raw_delete_reflog(const char *refname);
void test_refdb_raw_append_reflog(const char *refname);

int main(int argc, const char **argv)
{
	const char *delete = NULL;
	const char *reflog = NULL;
	const char *append_reflog = NULL;
	int delete_missing_error = 0;
	int clear_reflog = 0;
	struct refdb_config_data config_data = {NULL};

	struct option options[] = {
		OPT_STRING('d', NULL, &delete, "branch", "delete refdb entry"),
		OPT_STRING('l', NULL, &reflog, "branch", "show reflog"),
		OPT_STRING('a', NULL, &append_reflog, "branch", "append to reflog"),
		OPT_BOOL('c', NULL, &clear_reflog, "delete reflog. If a branch is provided, the reflog for that branch will be deleted; else all reflogs will be deleted."),
		OPT_BOOL('x', NULL, &delete_missing_error,
			 "deleting a missing key is an error"),
		OPT_END(),
	};

	argc = parse_options(argc, argv, "", options, test_refs_be_lmdb_usage,
			     0);

	if (!append_reflog && !clear_reflog && !delete && !reflog && argc != 1 && argc != 2)
		usage_with_options(test_refs_be_lmdb_usage,
				   options);

	git_config(git_default_config, NULL);

	config_data.refs_backend_type = "lmdb";
	config_data.refs_base = get_git_dir();

	register_refs_backend(&refs_be_lmdb);
	set_refs_backend("lmdb", &config_data);

	if (clear_reflog) {
		test_refdb_raw_delete_reflog(argv[0]);
	} else if (append_reflog) {
		test_refdb_raw_append_reflog(append_reflog);
	} else if (reflog) {
		return test_refdb_raw_reflog(reflog);
	} else if (delete) {
		if (test_refdb_raw_delete(delete) && delete_missing_error)
			return 1;
	} else if (argc == 1) {
		return test_refdb_raw_read(argv[0]);
	} else {
		test_refdb_raw_write(argv[0], argv[1]);
	}
	return 0;
}
