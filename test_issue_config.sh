#!/bin/bash
#
# Tests for issue_config.inc -- per-store policy: which users participate and
# which alert categories Claude may resolve unattended (the routine
# allowlist). Config lives with the store it governs, at
# $issue_store_root/config.json, so any machine reading a store reads the same
# policy and Claude's local triage loop consults the local store's config.
#
# Run:  bash test_issue_config.sh

set -u

here=$(cd "$(dirname "$0")" && pwd)

ISSUE_STORE_ROOT=$(mktemp -d -t issue_config_test.XXXXXX)
export ISSUE_STORE_ROOT
trap 'rm -rf "$ISSUE_STORE_ROOT"' EXIT

# shellcheck source=/dev/null
. "$here/issue_config.inc"

tests_run=0
tests_failed=0

Check()
{
    tests_run=$((tests_run + 1))
    if [ "$2" = "$3" ]; then
        echo "OK   $1"
    else
        tests_failed=$((tests_failed + 1))
        echo "FAIL $1"
        echo "       expected: [$2]"
        echo "       actual:   [$3]"
    fi
}

# ---- initialize the shared siena store's policy -------------------------

Init_store_config_if_absent shared '["nelson","christian","claude"]' '["low disk space"]'
Check "config file is created" "yes" "$([ -f "$(Store_config_file)" ] && echo yes || echo no)"
Check "store_kind is recorded" "shared" "$(Get_config_field store_kind)"
Check "participants are listed" "christian
claude
nelson" "$(Config_participants | sort)"
Check "routine allowlist seeded to 'low disk space'" "low disk space" "$(Config_routine_allowlist)"

# ---- category matching (all keywords of a category must appear) ---------

Is_routine_category "disk space low on m4"; Check "matches despite word reordering" 0 $?
Is_routine_category "/ at 98%: low disk space warning"; Check "matches exact phrasing" 0 $?
Is_routine_category "nodemon crashed on siena"; Check "unrelated alert is not routine" 1 $?
Is_routine_category "the disk looks fine"; Check "partial keyword overlap does not match" 1 $?

# ---- growing the allowlist later ----------------------------------------

Add_routine_category "stuck cron"
Check "added category is present" "low disk space
stuck cron" "$(Config_routine_allowlist)"
Is_routine_category "cron job is stuck on optima"; Check "newly added category matches" 0 $?
Add_routine_category "low disk space"
Check "adding a duplicate category is a no-op" "low disk space
stuck cron" "$(Config_routine_allowlist)"

# ---- init is non-clobbering ---------------------------------------------

Init_store_config_if_absent shared '["nelson"]' '["everything"]'
Check "re-init does not clobber an existing config" "low disk space
stuck cron" "$(Config_routine_allowlist)"

# ---- word-boundary matching (safety guardrail must not over-match) ------

# A keyword matches as a whole word, not a substring, so a single-word
# category like "cron" can't be tripped by "acronym".
Add_routine_category "cron"
Is_routine_category "acronym typo in a config file"; Check "substring-only keyword does not match" 1 $?
Is_routine_category "cron failed overnight"; Check "single-word category matches whole word" 0 $?

# ---- integrity ----------------------------------------------------------

Write_store_config shared '[1,2]' '["x"]' 2>/dev/null
Check "non-string participants are rejected" 1 $?

# ---- Summary ------------------------------------------------------------

echo "-------------------------------------------"
if [ "$tests_failed" -eq 0 ]; then
    echo "OK   all $tests_run tests passed"
    exit 0
else
    echo "FAIL $tests_failed of $tests_run tests failed"
    exit 1
fi
