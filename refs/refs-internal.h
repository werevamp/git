#ifndef REFS_REFS_INTERNAL_H
#define REFS_REFS_INTERNAL_H

/*
 * Data structures and functions for the internal use of the refs
 * module. Code outside of the refs module should use only the public
 * functions defined in "refs.h", and should *not* include this file.
 */

/*
 * Flag passed to lock_ref_sha1_basic() telling it to tolerate broken
 * refs (i.e., because the reference is about to be deleted anyway).
 */
#define REF_DELETING	0x02

/*
 * Used as a flag in ref_update::flags when a loose ref is being
 * pruned.
 */
#define REF_ISPRUNING	0x04

/*
 * Used as a flag in ref_update::flags when the reference should be
 * updated to new_sha1.
 */
#define REF_HAVE_NEW	0x08

/*
 * Used as a flag in ref_update::flags when old_sha1 should be
 * checked.
 */
#define REF_HAVE_OLD	0x10

/*
 * Used as a flag in ref_update::flags when the lockfile needs to be
 * committed.
 */
#define REF_NEEDS_COMMIT 0x20

/*
 * 0x40 is REF_FORCE_CREATE_REFLOG, so skip it if you're adding a
 * value to ref_update::flags
 */

/* Include broken references in a do_for_each_ref*() iteration */
#define DO_FOR_EACH_INCLUDE_BROKEN 0x01

/* Only include per-worktree refs in a do_for_each_ref*() iteration */
#define DO_FOR_EACH_PER_WORKTREE_ONLY 0x02

int do_for_each_per_worktree_ref(const char *submodule, const char *base,
				 each_ref_fn fn, int trim, int flags,
				 void *cb_data);

/*
 * Return true iff refname is minimally safe. "Safe" here means that
 * deleting a loose reference by this name will not do any damage, for
 * example by causing a file that is not a reference to be deleted.
 * This function does not check that the reference name is legal; for
 * that, use check_refname_format().
 *
 * We consider a refname that starts with "refs/" to be safe as long
 * as any ".." components that it might contain do not escape "refs/".
 * Names that do not start with "refs/" are considered safe iff they
 * consist entirely of upper case characters and '_' (like "HEAD" and
 * "MERGE_HEAD" but not "config" or "FOO/BAR").
 */
int refname_is_safe(const char *refname);

enum peel_status {
	/* object was peeled successfully: */
	PEEL_PEELED = 0,

	/*
	 * object cannot be peeled because the named object (or an
	 * object referred to by a tag in the peel chain), does not
	 * exist.
	 */
	PEEL_INVALID = -1,

	/* object cannot be peeled because it is not a tag: */
	PEEL_NON_TAG = -2,

	/* ref_entry contains no peeled value because it is a symref: */
	PEEL_IS_SYMREF = -3,

	/*
	 * ref_entry cannot be peeled because it is broken (i.e., the
	 * symbolic reference cannot even be resolved to an object
	 * name):
	 */
	PEEL_BROKEN = -4
};

/*
 * Peel the named object; i.e., if the object is a tag, resolve the
 * tag recursively until a non-tag is found.  If successful, store the
 * result to sha1 and return PEEL_PEELED.  If the object is not a tag
 * or is not valid, return PEEL_NON_TAG or PEEL_INVALID, respectively,
 * and leave sha1 unchanged.
 */
enum peel_status peel_object(const unsigned char *name, unsigned char *sha1);

/*
 * Return 0 if a reference named refname could be created without
 * conflicting with the name of an existing reference. Otherwise,
 * return a negative value and write an explanation to err. If extras
 * is non-NULL, it is a list of additional refnames with which refname
 * is not allowed to conflict. If skip is non-NULL, ignore potential
 * conflicts with refs in skip (e.g., because they are scheduled for
 * deletion in the same operation). Behavior is undefined if the same
 * name is listed in both extras and skip.
 *
 * Two reference names conflict if one of them exactly matches the
 * leading components of the other; e.g., "foo/bar" conflicts with
 * both "foo" and with "foo/bar/baz" but not with "foo/bar" or
 * "foo/barbados".
 *
 * extras and skip must be sorted.
 */
int verify_refname_available(const char *newname,
			     struct string_list *extras,
			     struct string_list *skip,
			     struct strbuf *err);

/*
 * Copy the reflog message msg to buf, which has been allocated sufficiently
 * large, while cleaning up the whitespaces.  Especially, convert LF to space,
 * because reflog file is one line per entry.
 */
int copy_reflog_msg(char *buf, const char *msg);

int should_autocreate_reflog(const char *refname);

/**
 * Information needed for a single ref update. Set new_sha1 to the new
 * value or to null_sha1 to delete the ref. To check the old value
 * while the ref is locked, set (flags & REF_HAVE_OLD) and set
 * old_sha1 to the old value, or to null_sha1 to ensure the ref does
 * not exist before update.
 */
struct ref_update {
	/*
	 * If (flags & REF_HAVE_NEW), set the reference to this value:
	 */
	unsigned char new_sha1[20];
	/*
	 * If (flags & REF_HAVE_OLD), check that the reference
	 * previously had this value:
	 */
	unsigned char old_sha1[20];
	/*
	 * One or more of REF_HAVE_NEW, REF_HAVE_OLD, REF_NODEREF,
	 * REF_DELETING, and REF_ISPRUNING:
	 */
	unsigned int flags;
	struct ref_lock *lock;
	int type;
	char *msg;
	const char refname[FLEX_ARRAY];
};

/*
 * Transaction states.
 * OPEN:   The transaction is in a valid state and can accept new updates.
 *         An OPEN transaction can be committed.
 * CLOSED: A closed transaction is no longer active and no other operations
 *         than free can be used on it in this state.
 *         A transaction can either become closed by successfully committing
 *         an active transaction or if there is a failure while building
 *         the transaction thus rendering it failed/inactive.
 */
enum ref_transaction_state {
	REF_TRANSACTION_OPEN   = 0,
	REF_TRANSACTION_CLOSED = 1
};

/*
 * Data structure for holding a reference transaction, which can
 * consist of checks and updates to multiple references, carried out
 * as atomically as possible.  This structure is opaque to callers.
 */
struct ref_transaction {
	struct ref_update **updates;
	size_t alloc;
	size_t nr;
	enum ref_transaction_state state;
};

int files_log_ref_write(const char *refname, const unsigned char *old_sha1,
			const unsigned char *new_sha1, const char *msg,
			int flags, struct strbuf *err);

/*
 * Check for entries in extras that are within the specified
 * directory, where dirname is a reference directory name including
 * the trailing slash (e.g., "refs/heads/foo/"). Ignore any
 * conflicting references that are found in skip. If there is a
 * conflicting reference, return its name.
 *
 * extras and skip must be sorted lists of reference names. Either one
 * can be NULL, signifying the empty list.
 */
const char *find_descendant_ref(const char *dirname,
				const struct string_list *extras,
				const struct string_list *skip);

int rename_ref_available(const char *oldname, const char *newname);

/* refs backends */
typedef int ref_transaction_commit_fn(struct ref_transaction *transaction,
				      struct strbuf *err);

/* reflog functions */
typedef int for_each_reflog_ent_fn(const char *refname,
				   each_reflog_ent_fn fn,
				   void *cb_data);
typedef int for_each_reflog_ent_reverse_fn(const char *refname,
					   each_reflog_ent_fn fn,
					   void *cb_data);
typedef int for_each_reflog_fn(each_ref_fn fn, void *cb_data);
typedef int reflog_exists_fn(const char *refname);
typedef int create_reflog_fn(const char *refname, int force_create,
			     struct strbuf *err);
typedef int delete_reflog_fn(const char *refname);
typedef int reflog_expire_fn(const char *refname, const unsigned char *sha1,
			     unsigned int flags,
			     reflog_expiry_prepare_fn prepare_fn,
			     reflog_expiry_should_prune_fn should_prune_fn,
			     reflog_expiry_cleanup_fn cleanup_fn,
			     void *policy_cb_data);

/* misc methods */
typedef int pack_refs_fn(unsigned int flags);
typedef int peel_ref_fn(const char *refname, unsigned char *sha1);
typedef int create_symref_fn(const char *ref_target,
			     const char *refs_heads_master,
			     const char *logmsg);
typedef int delete_refs_fn(struct string_list *refnames);

/* resolution methods */
typedef const char *resolve_ref_unsafe_fn(const char *ref,
					  int resolve_flags,
					  unsigned char *sha1, int *flags);
typedef int verify_refname_available_fn(const char *refname, struct string_list *extra, struct string_list *skip, struct strbuf *err);
typedef int resolve_gitlink_ref_fn(const char *path, const char *refname,
				   unsigned char *sha1);

/* iteration methods */
typedef int head_ref_fn(each_ref_fn fn, void *cb_data);
typedef int head_ref_submodule_fn(const char *submodule, each_ref_fn fn,
				  void *cb_data);
typedef int for_each_ref_fn(each_ref_fn fn, void *cb_data);
typedef int for_each_ref_submodule_fn(const char *submodule, each_ref_fn fn,
				      void *cb_data);
typedef int for_each_ref_in_fn(const char *prefix, each_ref_fn fn,
			       void *cb_data);
typedef int for_each_fullref_in_fn(const char *prefix, each_ref_fn fn,
				   void *cb_data, unsigned int broken);
typedef int for_each_ref_in_submodule_fn(const char *submodule,
					 const char *prefix,
					 each_ref_fn fn, void *cb_data);
typedef int for_each_rawref_fn(each_ref_fn fn, void *cb_data);
typedef int for_each_namespaced_ref_fn(each_ref_fn fn, void *cb_data);
typedef int for_each_replace_ref_fn(each_ref_fn fn, void *cb_data);

struct ref_be {
	struct ref_be *next;
	const char *name;
	ref_transaction_commit_fn *transaction_commit;
	ref_transaction_commit_fn *initial_transaction_commit;

	for_each_reflog_ent_fn *for_each_reflog_ent;
	for_each_reflog_ent_reverse_fn *for_each_reflog_ent_reverse;
	for_each_reflog_fn *for_each_reflog;
	reflog_exists_fn *reflog_exists;
	create_reflog_fn *create_reflog;
	delete_reflog_fn *delete_reflog;
	reflog_expire_fn *reflog_expire;

	pack_refs_fn *pack_refs;
	peel_ref_fn *peel_ref;
	create_symref_fn *create_symref;
	delete_refs_fn *delete_refs;

	resolve_ref_unsafe_fn *resolve_ref_unsafe;
	verify_refname_available_fn *verify_refname_available;
	resolve_gitlink_ref_fn *resolve_gitlink_ref;

	head_ref_fn *head_ref;
	head_ref_submodule_fn *head_ref_submodule;
	for_each_ref_fn *for_each_ref;
	for_each_ref_submodule_fn *for_each_ref_submodule;
	for_each_ref_in_fn *for_each_ref_in;
	for_each_fullref_in_fn *for_each_fullref_in;
	for_each_ref_in_submodule_fn *for_each_ref_in_submodule;
	for_each_rawref_fn *for_each_rawref;
	for_each_namespaced_ref_fn *for_each_namespaced_ref;
	for_each_replace_ref_fn *for_each_replace_ref;
};

#endif /* REFS_REFS_INTERNAL_H */
