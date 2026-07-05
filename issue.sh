#!/bin/bash
#
# issue.sh -- command-line surface over the threaded-issue store. This is what
# non-sourcing callers use: scheduled tasks and alert.sh (to register a
# problem), the Claude triage poller (to read/claim/answer/close), and a human
# appending an answer over ssh.
#
# All state lives under $ISSUE_STORE_ROOT (default $HOME/alerts); each machine
# runs its own store, so this script always operates on the local store.
#
# Usage:
#   issue.sh create <subject> <author> <kind> [severity]   # body on stdin -> id
#   issue.sh append <id> <author> <kind> [options-json]    # text on stdin
#   issue.sh claim <id> <owner>
#   issue.sh set-state <id> <state>
#   issue.sh state <id>
#   issue.sh subject <id>
#   issue.sh render <id>
#   issue.sh unread <user>
#   issue.sh seen <id> <user>
#   issue.sh is-routine <subject>                          # exit 0 routine
#   issue.sh init-config <kind> <participants-json> <allowlist-json>
#   issue.sh add-category <category>
#   issue.sh participants

set -u

here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=/dev/null
. "$here/issue_config.inc"

Usage()
{
    # Emit the header usage block (the comment lines above) and fail.
    echo "FAIL issue.sh: $1" 1>&2
    grep '^#   issue.sh' "$0" | sed 's/^#   /  /' 1>&2
    exit 1
}

Require_argc()
{
    # $1 = minimum arg count still in $@ (excluding the subcommand), $2 = the
    # actual count, $3 = subcommand name for the diagnostic.
    [ "$2" -ge "$1" ] || Usage "'$3' needs at least $1 argument(s)"
}

cmd=${1:-}
shift 2>/dev/null || true

# Subcommands are ordered alphabetically. Each is a thin pass-through to a
# library function; the script's exit status is that function's, so exit-code
# contracts (claim, is-routine) propagate to the caller unchanged.
case "$cmd" in
    add-category)
        Require_argc 1 $# add-category
        Add_routine_category "$1"
    ;;
    append)
        Require_argc 3 $# append
        Append_message "$1" "$2" "$3" "${4:-}"
    ;;
    claim)
        Require_argc 2 $# claim
        Claim_issue "$1" "$2"
    ;;
    create)
        Require_argc 3 $# create
        Create_issue "$1" "$2" "$3" "${4:-normal}"
    ;;
    init-config)
        Require_argc 3 $# init-config
        Init_store_config_if_absent "$1" "$2" "$3"
    ;;
    is-routine)
        Require_argc 1 $# is-routine
        Is_routine_category "$1"
    ;;
    participants)
        Config_participants
    ;;
    render)
        Require_argc 1 $# render
        Render_thread "$1"
    ;;
    seen)
        Require_argc 2 $# seen
        Mark_issue_seen_for "$1" "$2"
    ;;
    set-state)
        Require_argc 2 $# set-state
        Set_issue_state "$1" "$2"
    ;;
    state)
        Require_argc 1 $# state
        Get_issue_state "$1"
    ;;
    subject)
        Require_argc 1 $# subject
        Get_issue_subject "$1"
    ;;
    unread)
        Require_argc 1 $# unread
        Find_unread_issues_for "$1"
    ;;
    *)
        Usage "unknown subcommand '$cmd'"
    ;;
esac
