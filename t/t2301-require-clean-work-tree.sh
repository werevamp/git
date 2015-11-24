#!/bin/sh

test_description='require_clean_work_tree'

. ./test-lib.sh

run_require_clean_work_tree () {
	(
		. "$(git --exec-path)"/git-sh-setup &&
		require_clean_work_tree "do-something"
	)
}

test_expect_success 'setup' '
	test_commit initial file
'

test_expect_success 'success on clean index and worktree' '
	run_require_clean_work_tree
'

test_expect_success 'error on dirty worktree' '
	test_when_finished "git reset --hard" &&
	echo dirty >file &&
	test_must_fail run_require_clean_work_tree
'

test_expect_success 'error on dirty index' '
	test_when_finished "git reset --hard" &&
	echo dirty >file &&
	git add file &&
	test_must_fail run_require_clean_work_tree
'

test_expect_success 'error on dirty index and worktree' '
	test_when_finished "git reset --hard" &&
	echo dirty >file &&
	git add file &&
	echo dirtier >file &&
	test_must_fail run_require_clean_work_tree
'

test_expect_success 'error on clean index and worktree while on orphan branch' '
	test_when_finished "git checkout master" &&
	git checkout --orphan orphan &&
	git reset --hard &&
	test_must_fail run_require_clean_work_tree
'

test_expect_success 'error on dirty index while on orphan branch' '
	test_when_finished "git checkout master" &&
	git checkout --orphan orphan &&
	test_must_fail run_require_clean_work_tree
'

test_expect_success 'error on dirty index and work tree while on orphan branch' '
	test_when_finished "git checkout master" &&
	git checkout --orphan orphan &&
	echo dirty >file &&
	test_must_fail run_require_clean_work_tree
'

test_done
