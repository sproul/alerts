#
# issue_store.inc -- a threaded-issue store layered on top of the existing
# file+SSH alert system. Each issue is a directory holding an append-only
# thread of messages (report -> notes -> question -> answer -> resolution)
# plus a lifecycle state, so Claude and the engineers can converse about a
# problem and hand it back and forth.
#
# Storage model (mirrors the proven $HOME/alerts/all + seen/<user> pattern):
#   $issue_store_root/issues/<issue_id>/
#       meta.json               one object: issue_id, subject, origin_host, ...
#       state                   one lifecycle word (new|claimed|awaiting_human|
#                               resolved|review|closed)
#       messages/<NNNN>.json    one message per file; NNNN gives total order
#       seen/<user>/<NNNN>      marker: message NNNN has been seen by <user>
#       claim              file created atomically via ln; its content is
#                          the claimant's name (no empty-owner window)
#
# Design constraints honoured here:
#   * No flock (absent on macOS) -- atomicity comes from mkdir and ln, which
#     are atomic on every POSIX filesystem we run on. This assumes the store
#     lives on a single hardlink-capable filesystem (a normal $HOME); a store
#     placed on exFAT / FAT / some network mounts would break ln-based slot
#     claiming. Keep $issue_store_root on a local POSIX filesystem.
#   * All JSON is built and parsed by python3 (already a repo dependency), so
#     arbitrary alert text round-trips without shell/JSON injection, and a
#     corrupt on-disk file is reported as a fatal data error, not a traceback.
#   * Source this file; it defines functions and one global. It never sets
#     -e/-u so it is safe to source into any bash shell (it uses bash-only
#     features: local, $RANDOM).

# The store root is a wide-impact setting, so it lives in a global (overridable
# by the environment for tests) rather than being threaded through every call.
issue_store_root="${ISSUE_STORE_ROOT:-$HOME/alerts}"

# ---- small shared helpers ----------------------------------------------

Validate_name_token()
{
    # Guard a value that becomes a filesystem path component (issue id,
    # user/owner/kind name) against path traversal and shell surprises.
    # $1 = label for diagnostics, $2 = token.
    case "$2" in
        ''|*[!a-zA-Z0-9_-]*)
            echo "FAIL bad $1 '$2' (alphanumeric, _, - only)" 1>&2
            return 1
        ;;
    esac
    return 0
}

Now_iso()
{
    date -u +%Y-%m-%dT%H:%M:%SZ
}

Issue_dir()
{
    # Echo the directory for issue $1 (no existence check).
    echo "$issue_store_root/issues/$1"
}

Message_path()
{
    # Echo the file path for message seq $2 of issue $1.
    printf '%s/messages/%04d.json' "$(Issue_dir "$1")" "$2"
}

Require_issue()
{
    # Return 0 iff issue $1 exists; otherwise emit a FAIL diagnostic naming
    # the calling context ($2) and return 1.
    [ -d "$(Issue_dir "$1")/messages" ] && return 0
    echo "FAIL $2: no such issue '$1'" 1>&2
    return 1
}

# ---- issue creation ------------------------------------------------------

New_issue_id()
{
    # Generate a sortable id: <UTC timestamp>_<host>_<rand>. Uniqueness is
    # enforced atomically by Reserve_new_issue_dir, not here.
    local host
    host=$(hostname -s 2>/dev/null)
    host=$(printf '%s' "$host" | tr -c 'a-zA-Z0-9_-' '_')
    printf '%s_%s_%s\n' "$(date -u +%Y%m%d%H%M%S)" "${host:-host}" "$RANDOM"
}

Reserve_new_issue_dir()
{
    # Atomically reserve a fresh issue directory and echo its id. mkdir of the
    # issue dir fails if the id was taken between generation and creation, so a
    # same-second/same-$RANDOM clash is detected and retried rather than
    # silently merged into an existing issue.
    local id dir tries=0
    mkdir -p "$issue_store_root/issues" || return 1
    while [ "$tries" -lt 1000 ]; do
        id=$(New_issue_id)
        dir=$(Issue_dir "$id")
        if mkdir "$dir" 2>/dev/null; then
            echo "$id"
            return 0
        fi
        tries=$((tries + 1))
    done
    echo "FAIL Reserve_new_issue_dir: could not reserve a unique id after $tries tries" 1>&2
    return 1
}

Encode_meta_json()
{
    # args: issue_id subject severity origin_host created_ts
    python3 -c '
import json, sys
keys = ["issue_id", "subject", "severity", "origin_host", "created_ts"]
print(json.dumps(dict(zip(keys, sys.argv[1:6]))))
' "$@"
}

Write_issue_meta()
{
    # $1 id, $2 subject, $3 severity. Written atomically (temp + rename).
    local dir tmp
    dir=$(Issue_dir "$1")
    tmp=$(mktemp "$dir/.meta.XXXXXX") || return 1
    Encode_meta_json "$1" "$2" "$3" "$(hostname -s 2>/dev/null)" "$(Now_iso)" > "$tmp" \
        || { rm -f "$tmp"; return 1; }
    mv "$tmp" "$dir/meta.json"
}

Create_issue()
{
    # Create a new issue from the report body on stdin; echo its id.
    # $1 subject, $2 author, $3 kind (usually 'report'), $4 severity
    # (optional, default 'normal').
    local subject=$1 author=$2 kind=$3 severity=${4:-normal} id dir
    Validate_name_token author "$author" || return 1
    Validate_name_token kind "$kind" || return 1
    id=$(Reserve_new_issue_dir) || return 1
    dir=$(Issue_dir "$id")
    mkdir -p "$dir/messages" "$dir/seen" \
        || { echo "FAIL Create_issue: could not create layout for '$id'" 1>&2; return 1; }
    Write_issue_meta "$id" "$subject" "$severity" || return 1
    Set_issue_state "$id" new || return 1
    Append_message "$id" "$author" "$kind" >/dev/null || return 1
    echo "$id"
}

# ---- messages ------------------------------------------------------------

Encode_message_json()
{
    # args: author kind ts [options-json-array]. Message text on stdin.
    python3 -c '
import json, sys
author, kind, ts = sys.argv[1:4]
options = sys.argv[4] if len(sys.argv) > 4 else ""
obj = {"ts": ts, "author": author, "kind": kind, "text": sys.stdin.read()}
if options:
    parsed = json.loads(options)
    if not isinstance(parsed, list) or not all(isinstance(x, str) for x in parsed):
        sys.stderr.write("FAIL Encode_message_json: options must be a JSON array of strings\n")
        sys.exit(1)
    obj["options"] = parsed
print(json.dumps(obj))
' "$@"
}

Count_message_files()
{
    # Echo the number of NNNN.json message files in directory $1.
    local n=0 f
    for f in "$1"/*.json; do
        [ -e "$f" ] && n=$((n + 1))
    done
    echo "$n"
}

Max_message_seq()
{
    # Echo the highest NNNN among message files in directory $1, or 0 if
    # none. The next append slot derives from this (not from the file count)
    # so a removed message can never wedge appends onto an occupied slot.
    local max=0 f base n
    for f in "$1"/*.json; do
        [ -e "$f" ] || continue
        base=$(basename "$f" .json)
        case "$base" in
            ''|*[!0-9]*) continue ;;
        esac
        n=$((10#$base))
        [ "$n" -gt "$max" ] && max=$n
    done
    echo "$max"
}

Install_message_atomically()
{
    # Claim the next free NNNN.json slot in $1 for the prepared temp file $2
    # via ln (atomic; fails if the slot exists), retrying on a lost race.
    # Echo the winning seq number.
    local msgs=$1 tmp=$2 tries=0 n dest
    while [ "$tries" -lt 1000 ]; do
        n=$(( $(Max_message_seq "$msgs") + 1 ))
        dest=$(printf '%s/%04d.json' "$msgs" "$n")
        if ln "$tmp" "$dest" 2>/dev/null; then
            rm -f "$tmp"
            echo "$n"
            return 0
        fi
        tries=$((tries + 1))
    done
    rm -f "$tmp"
    echo "FAIL Install_message_atomically: no free slot in $msgs after $tries tries" 1>&2
    return 1
}

Append_message()
{
    # Append a message (text on stdin) to issue $1; echo its seq number.
    # $2 author, $3 kind, $4 options-json-array (optional).
    local id=$1 author=$2 kind=$3 options=${4:-} dir tmp
    Validate_name_token issue_id "$id" || return 1
    Validate_name_token author "$author" || return 1
    Validate_name_token kind "$kind" || return 1
    Require_issue "$id" Append_message || return 1
    dir=$(Issue_dir "$id")
    tmp=$(mktemp "$dir/messages/.msg.XXXXXX") || return 1
    Encode_message_json "$author" "$kind" "$(Now_iso)" "$options" > "$tmp" \
        || { rm -f "$tmp"; echo "FAIL Append_message: could not encode message for '$id'" 1>&2; return 1; }
    Install_message_atomically "$dir/messages" "$tmp"
}

Get_message_field()
{
    # Echo field $3 of message $2 of issue $1. The pseudo-field 'options_N'
    # returns the Nth (0-based) entry of the options array.
    local mf
    mf=$(Message_path "$1" "$2")
    [ -f "$mf" ] || { echo "FAIL Get_message_field: no message $2 in '$1'" 1>&2; return 1; }
    python3 -c '
import json, sys
try:
    obj = json.load(open(sys.argv[1]))
except Exception as e:
    sys.stderr.write("FAIL Get_message_field: corrupt message file %s: %s\n" % (sys.argv[1], e))
    sys.exit(1)
field = sys.argv[2]
if field.startswith("options_"):
    idx = int(field.split("_", 1)[1])
    opts = obj.get("options", [])
    sys.stdout.write(opts[idx] if idx < len(opts) else "")
else:
    sys.stdout.write(str(obj.get(field, "")))
' "$mf" "$3"
}

Count_issue_messages()
{
    Count_message_files "$(Issue_dir "$1")/messages"
}

# ---- lifecycle state -----------------------------------------------------

Set_issue_state()
{
    # $1 id, $2 state. Written atomically (temp + rename).
    local dir tmp
    Validate_name_token state "$2" || return 1
    dir=$(Issue_dir "$1")
    [ -d "$dir" ] || { echo "FAIL Set_issue_state: no such issue '$1'" 1>&2; return 1; }
    tmp=$(mktemp "$dir/.state.XXXXXX") || return 1
    printf '%s\n' "$2" > "$tmp"
    mv "$tmp" "$dir/state"
}

Get_issue_state()
{
    local dir
    dir=$(Issue_dir "$1")
    [ -f "$dir/state" ] || { echo "FAIL Get_issue_state: no state for '$1'" 1>&2; return 1; }
    cat "$dir/state"
}

Read_meta_field()
{
    # Echo field $2 from issue $1's meta.json.
    local dir
    dir=$(Issue_dir "$1")
    [ -f "$dir/meta.json" ] || { echo "FAIL Read_meta_field: no meta for '$1'" 1>&2; return 1; }
    python3 -c '
import json, sys
try:
    print(json.load(open(sys.argv[1])).get(sys.argv[2], ""))
except (ValueError, OSError) as e:
    sys.stderr.write("FAIL Read_meta_field: corrupt meta file %s: %s\n" % (sys.argv[1], e))
    sys.exit(1)
' "$dir/meta.json" "$2"
}

Get_issue_subject()
{
    Read_meta_field "$1" subject
}

# ---- claim mutex ---------------------------------------------------------

Get_issue_claimant()
{
    local claim_file
    claim_file="$(Issue_dir "$1")/claim"
    [ -f "$claim_file" ] && cat "$claim_file"
}

Claim_issue()
{
    # Atomically claim issue $1 for owner $2. Return 0 if $2 holds the claim
    # (freshly or already); return 1 if someone else holds it. The claim file
    # is pre-filled with the owner name and linked into place with ln, so it
    # never exists in an empty (owner-unknown) state.
    local id=$1 owner=$2 dir tmp held
    Validate_name_token issue_id "$id" || return 1
    Validate_name_token owner "$owner" || return 1
    Require_issue "$id" Claim_issue || return 1
    dir=$(Issue_dir "$id")
    tmp=$(mktemp "$dir/.claim.XXXXXX") || return 1
    printf '%s\n' "$owner" > "$tmp"
    if ln "$tmp" "$dir/claim" 2>/dev/null; then
        rm -f "$tmp"
        echo "OK Claim_issue: $id claimed by $owner" 1>&2
        return 0
    fi
    rm -f "$tmp"
    held=$(Get_issue_claimant "$id")
    if [ "$held" = "$owner" ]; then
        echo "OK Claim_issue: $id already held by $owner" 1>&2
        return 0
    fi
    echo "FAIL Claim_issue: $id already held by ${held:-?}" 1>&2
    return 1
}

# ---- per-user unread tracking -------------------------------------------

Mark_issue_seen_for()
{
    # Mark every current message of issue $1 as seen by user $2.
    local id=$1 user=$2 dir seen f
    Validate_name_token user "$user" || return 1
    Require_issue "$id" Mark_issue_seen_for || return 1
    dir=$(Issue_dir "$id")
    seen="$dir/seen/$user"
    mkdir -p "$seen" || return 1
    for f in "$dir/messages"/*.json; do
        [ -e "$f" ] || continue
        touch "$seen/$(basename "$f" .json)"
    done
}

Issue_has_unseen_for()
{
    # Return 0 iff issue $1 has at least one message with no seen-marker
    # for user $2.
    local id=$1 user=$2 dir seen f base
    dir=$(Issue_dir "$id")
    seen="$dir/seen/$user"
    for f in "$dir/messages"/*.json; do
        [ -e "$f" ] || continue
        base=$(basename "$f" .json)
        [ -e "$seen/$base" ] || return 0
    done
    return 1
}

Find_unread_issues_for()
{
    # Print, one id per line, every issue with unseen messages for user $1.
    local user=$1 issues_dir d id
    Validate_name_token user "$user" || return 1
    issues_dir="$issue_store_root/issues"
    [ -d "$issues_dir" ] || return 0
    for d in "$issues_dir"/*/; do
        [ -d "$d" ] || continue
        id=$(basename "$d")
        Issue_has_unseen_for "$id" "$user" && echo "$id"
    done
}

# ---- rendering (what a human / Claude reads) ----------------------------

Render_messages_dir()
{
    # Format every message in directory $1 in chronological (NNNN) order,
    # in a single python pass. A corrupt message file is a fatal data error.
    python3 -c '
import glob, json, os, sys
for path in sorted(glob.glob(os.path.join(sys.argv[1], "*.json"))):
    try:
        o = json.load(open(path))
    except (ValueError, OSError) as e:
        sys.stderr.write("FAIL Render_thread: corrupt message file %s: %s\n" % (path, e))
        sys.exit(1)
    print("[%s] %s (%s): %s" % (o.get("ts", ""), o.get("author", ""),
                                o.get("kind", ""), o.get("text", "").rstrip("\n")))
    opts = o.get("options")
    if opts:
        print("    options: " + " | ".join(opts))
' "$1"
}

Render_thread_header()
{
    printf '=== issue %s [%s] ===\n' "$1" "$(Get_issue_state "$1")"
    printf 'subject: %s\n' "$(Get_issue_subject "$1")"
}

Render_thread()
{
    # Human/Claude-readable dump of issue $1: header then each message in
    # chronological (NNNN) order.
    local id=$1
    Require_issue "$id" Render_thread || return 1
    Render_thread_header "$id"
    Render_messages_dir "$(Issue_dir "$id")/messages"
}
