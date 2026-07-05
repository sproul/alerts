#!/bin/bash
#
# Tests for issue_store.inc -- the threaded-issue store that lets Claude and
# the engineers converse about an alert (report -> notes -> question ->
# answer -> resolution) with a per-issue lifecycle state.
#
# Storage model (mirrors the proven $HOME/alerts/all + seen/<user> pattern):
#   $issue_store_root/issues/<issue_id>/
#       meta.json               one object: issue_id, subject, origin_host, ...
#       state                   one lifecycle word
#       messages/<NNNN>.json    one message per file; NNNN gives total order
#       seen/<user>/<NNNN>      marker: that message has been seen by <user>
#       claim/                  mkdir-mutex; claim/owner names the claimant
#
# Run:  bash test_issue_store.sh

set -u

here=$(cd "$(dirname "$0")" && pwd)

# Isolate the store in a throwaway dir so tests never touch real alerts.
ISSUE_STORE_ROOT=$(mktemp -d -t issue_store_test.XXXXXX)
export ISSUE_STORE_ROOT
trap 'rm -rf "$ISSUE_STORE_ROOT"' EXIT

# shellcheck source=/dev/null
. "$here/issue_store.inc"

tests_run=0
tests_failed=0

Check()
{
    # $1 human description, $2 expected, $3 actual
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

Check_exit()
{
    # $1 description, $2 expected exit code, $3 actual exit code
    Check "$1" "$2" "$3"
}

Check_contains()
{
    # $1 description, $2 needle, $3 haystack
    tests_run=$((tests_run + 1))
    case "$3" in
        *"$2"*)
            echo "OK   $1"
        ;;
        *)
            tests_failed=$((tests_failed + 1))
            echo "FAIL $1"
            echo "       needle not found: [$2]"
            echo "       in:               [$3]"
        ;;
    esac
}

# ---- Create_issue -------------------------------------------------------

id=$(echo "df shows 98% used" | Create_issue "disk space low on m4" system report)
Check "Create_issue returns a non-empty id" "non-empty" "$([ -n "$id" ] && echo non-empty || echo empty)"
Check "new issue starts in state 'new'" "new" "$(Get_issue_state "$id")"
Check "new issue records its subject in meta" "disk space low on m4" "$(Get_issue_subject "$id")"
Check "new issue has exactly one message" "1" "$(Count_issue_messages "$id")"
Check "first message kind is 'report'" "report" "$(Get_message_field "$id" 1 kind)"
Check "first message author is 'system'" "system" "$(Get_message_field "$id" 1 author)"
Check "first message text preserved" "df shows 98% used" "$(Get_message_field "$id" 1 text)"

# ---- Append_message ordering -------------------------------------------

echo "taking a look" | Append_message "$id" claude note >/dev/null
Check "append increments message count" "2" "$(Count_issue_messages "$id")"
Check "second message author is 'claude'" "claude" "$(Get_message_field "$id" 2 author)"

# Bodies with shell/JSON metacharacters must round-trip verbatim.
tricky='he said "rm -rf $HOME" & `backtick` \ end'
echo "$tricky" | Append_message "$id" claude note >/dev/null
Check "metacharacter body round-trips" "$tricky" "$(Get_message_field "$id" 3 text)"

# ---- Claim mutex --------------------------------------------------------

Claim_issue "$id" claude; Check_exit "first claim succeeds" 0 $?
Claim_issue "$id" claude; Check_exit "re-claim by same owner is idempotent" 0 $?
Claim_issue "$id" christian 2>/dev/null; Check_exit "claim by a different owner is refused" 1 $?
Check "claim owner is the first claimant" "claude" "$(Get_issue_claimant "$id")"

# ---- State transitions --------------------------------------------------

Set_issue_state "$id" awaiting_human
Check "state transition persists" "awaiting_human" "$(Get_issue_state "$id")"

# ---- Per-user unread tracking ------------------------------------------

Check_contains "fresh issue is unread for christian" "$id" "$(Find_unread_issues_for christian)"
Mark_issue_seen_for "$id" christian
Check "after marking seen, issue is not unread for christian" "" "$(Find_unread_issues_for christian)"
echo "strategy A or B?" | Append_message "$id" claude question '["A","B"]' >/dev/null
Check_contains "a new message makes the issue unread again" "$id" "$(Find_unread_issues_for christian)"
Check "question message carries its options" "A" "$(Get_message_field "$id" 4 options_0)"

# ---- Thread rendering (what a human / Claude reads) --------------------

thread=$(Render_thread "$id")
Check_contains "rendered thread shows the report" "df shows 98% used" "$thread"
Check_contains "rendered thread shows claude's question" "strategy A or B?" "$thread"
# Report must appear before the question in the rendered order.
report_line=$(echo "$thread" | grep -n "df shows 98% used" | head -1 | cut -d: -f1)
question_line=$(echo "$thread" | grep -n "strategy A or B?" | head -1 | cut -d: -f1)
Check "thread renders in chronological order" "before" "$([ "$report_line" -lt "$question_line" ] && echo before || echo after)"

# ---- Validation / integrity (fatal, per project policy) ----------------

Append_message "../escape" claude note </dev/null 2>/dev/null; Check_exit "path-traversal issue_id is rejected" 1 $?
echo x | Append_message "no_such_issue_9999" claude note 2>/dev/null; Check_exit "append to a missing issue fails loudly" 1 $?
Claim_issue "$id" "bad owner!" 2>/dev/null; Check_exit "malformed owner name is rejected" 1 $?

# ---- robustness: a gap in the message seq must not wedge appends --------

gap_id=$(echo "start" | Create_issue "gap test" system report)
echo "m2" | Append_message "$gap_id" claude note >/dev/null
echo "m3" | Append_message "$gap_id" claude note >/dev/null
rm -f "$(Message_path "$gap_id" 2)"   # punch a hole at seq 0002
echo "m4" | Append_message "$gap_id" claude note >/dev/null
Check_exit "append still succeeds despite a gap in the seq" 0 $?
Check "append after a gap lands above the max seq (0004)" "m4" "$(Get_message_field "$gap_id" 4 text)"

# ---- integrity: options must be a JSON array of strings -----------------

echo "q" | Append_message "$id" claude question '[1,2]' 2>/dev/null
Check_exit "non-string options are rejected" 1 $?
echo "q" | Append_message "$id" claude question '{"a":1}' 2>/dev/null
Check_exit "non-array options are rejected" 1 $?
echo "q" | Append_message "$id" claude question '["X","Y"]' >/dev/null
Check_exit "valid string-array options are accepted" 0 $?

# ---- Summary ------------------------------------------------------------

echo "-------------------------------------------"
if [ "$tests_failed" -eq 0 ]; then
    echo "OK   all $tests_run tests passed"
    exit 0
else
    echo "FAIL $tests_failed of $tests_run tests failed"
    exit 1
fi
