#!/bin/bash
#
# Tests for issue.sh -- the command-line surface over issue_store.inc /
# issue_config.inc that non-sourcing callers use (cron tasks, alert.sh, the
# Claude triage poller, and a human appending an answer over ssh).
#
# Run:  bash test_issue_cli.sh

set -u

here=$(cd "$(dirname "$0")" && pwd)
cli="bash $here/issue.sh"

ISSUE_STORE_ROOT=$(mktemp -d -t issue_cli_test.XXXXXX)
export ISSUE_STORE_ROOT
trap 'rm -rf "$ISSUE_STORE_ROOT"' EXIT

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

Check_contains()
{
    tests_run=$((tests_run + 1))
    case "$3" in
        *"$2"*) echo "OK   $1" ;;
        *)
            tests_failed=$((tests_failed + 1))
            echo "FAIL $1"
            echo "       needle: [$2]"
            echo "       in:     [$3]"
        ;;
    esac
}

# ---- provisioning the shared siena store --------------------------------

$cli init-config shared '["nelson","christian","claude"]' '["low disk space"]' 2>/dev/null
Check "init-config exits ok" 0 $?

# ---- create / read ------------------------------------------------------

id=$(echo "df shows / at 98%" | $cli create "disk space low on m4" system report)
Check "create returns a non-empty id" "non-empty" "$([ -n "$id" ] && echo non-empty || echo empty)"
Check "state is new" "new" "$($cli state "$id")"
Check "subject round-trips" "disk space low on m4" "$($cli subject "$id")"

# ---- append / render ----------------------------------------------------

echo "looking into it" | $cli append "$id" claude note >/dev/null
Check_contains "render shows the appended note" "looking into it" "$($cli render "$id")"

# ---- claim --------------------------------------------------------------

$cli claim "$id" claude 2>/dev/null;      Check "claim by claude succeeds" 0 $?
$cli claim "$id" christian 2>/dev/null;   Check "claim by another user is refused" 1 $?

# ---- state transition ---------------------------------------------------

$cli set-state "$id" awaiting_human
Check "set-state persists" "awaiting_human" "$($cli state "$id")"

# ---- unread / seen ------------------------------------------------------

Check_contains "issue is unread for christian" "$id" "$($cli unread christian)"
$cli seen "$id" christian
Check "issue no longer unread after seen" "" "$($cli unread christian)"

# ---- routine-category classification ------------------------------------

$cli is-routine "disk space low on m4"; Check "known category is routine" 0 $?
$cli is-routine "nodemon crashed on siena"; Check "unknown category is not routine" 1 $?

# ---- misuse -------------------------------------------------------------

$cli bogus-subcommand 2>/dev/null;  Check "unknown subcommand fails" 1 $?
$cli create 2>/dev/null;            Check "missing args fail" 1 $?

# ---- Summary ------------------------------------------------------------

echo "-------------------------------------------"
if [ "$tests_failed" -eq 0 ]; then
    echo "OK   all $tests_run tests passed"
    exit 0
else
    echo "FAIL $tests_failed of $tests_run tests failed"
    exit 1
fi
