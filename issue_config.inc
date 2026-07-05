#
# issue_config.inc -- per-store policy that sits alongside the issue store:
#   * participants: which users this store's threads are addressed to
#   * routine_allowlist: the alert categories Claude may resolve unattended;
#     anything not matching the allowlist must be handed back with a question
#     rather than auto-fixed.
#
# Policy is co-located with the data it governs, at $issue_store_root/config.json,
# so a store carries its own policy: whichever machine hosts a store, Claude's
# local triage loop reads that store's config to decide what it may touch.
#
# Source this file; it pulls in issue_store.inc (for $issue_store_root and the
# shared conventions) from the same directory.

_issue_config_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=/dev/null
. "$_issue_config_dir/issue_store.inc"

Store_config_file()
{
    echo "$issue_store_root/config.json"
}

# ---- writing policy ------------------------------------------------------

Write_store_config()
{
    # $1 store_kind, $2 participants (JSON array of strings), $3
    # routine_allowlist (JSON array of strings). Written atomically; the JSON
    # arrays are validated so a malformed policy is a fatal error, not a file
    # that silently misbehaves later.
    local kind=$1 participants=$2 allowlist=$3 cfg tmp
    mkdir -p "$issue_store_root" || return 1
    cfg=$(Store_config_file)
    tmp=$(mktemp "$issue_store_root/.config.XXXXXX") || return 1
    python3 -c '
import json, sys
kind, participants, allowlist, out = sys.argv[1:5]
p = json.loads(participants)
a = json.loads(allowlist)
def bad(name):
    sys.stderr.write("FAIL Write_store_config: %s must be a JSON array of strings\n" % name)
    sys.exit(1)
if not (isinstance(p, list) and all(isinstance(x, str) for x in p)):
    bad("participants")
if not (isinstance(a, list) and all(isinstance(x, str) for x in a)):
    bad("routine_allowlist")
json.dump({"store_kind": kind, "participants": p, "routine_allowlist": a},
          open(out, "w"), indent=2)
' "$kind" "$participants" "$allowlist" "$tmp" || { rm -f "$tmp"; return 1; }
    mv "$tmp" "$cfg" \
        || { rm -f "$tmp"; echo "FAIL Write_store_config: could not install $cfg" 1>&2; return 1; }
    echo "OK Write_store_config: wrote $cfg" 1>&2
}

Init_store_config_if_absent()
{
    # Like Write_store_config, but leaves an existing config untouched so a
    # re-run of the installer never clobbers a hand-edited allowlist.
    local cfg
    cfg=$(Store_config_file)
    if [ -f "$cfg" ]; then
        echo "OK Init_store_config: config already present at $cfg" 1>&2
        return 0
    fi
    Write_store_config "$@"
}

Add_routine_category()
{
    # Append category $1 to routine_allowlist (no-op if already present).
    # This is a read-modify-write and is NOT concurrency-safe; it assumes the
    # only writers are manual admin edits (init-config / add-category), which
    # are serialized in practice. The Claude triage loop only ever READS the
    # config, so it cannot race this.
    local cat=$1 cfg tmp
    cfg=$(Store_config_file)
    [ -f "$cfg" ] || { echo "FAIL Add_routine_category: no config at $cfg" 1>&2; return 1; }
    tmp=$(mktemp "$issue_store_root/.config.XXXXXX") || return 1
    python3 -c '
import json, sys
cfg, cat, out = sys.argv[1:4]
d = json.load(open(cfg))
allow = d.get("routine_allowlist", [])
if cat not in allow:
    allow.append(cat)
    d["routine_allowlist"] = allow
json.dump(d, open(out, "w"), indent=2)
' "$cfg" "$cat" "$tmp" || { rm -f "$tmp"; return 1; }
    mv "$tmp" "$cfg"
}

# ---- reading policy ------------------------------------------------------

Get_config_field()
{
    # Echo scalar field $1 from the store config.
    local cfg
    cfg=$(Store_config_file)
    [ -f "$cfg" ] || { echo "FAIL Get_config_field: no config at $cfg" 1>&2; return 1; }
    python3 -c '
import json, sys
try:
    print(json.load(open(sys.argv[1])).get(sys.argv[2], ""))
except (ValueError, OSError) as e:
    sys.stderr.write("FAIL Get_config_field: corrupt config %s: %s\n" % (sys.argv[1], e))
    sys.exit(1)
' "$cfg" "$1"
}

Get_config_array()
{
    # Echo array field $1 from the store config, one element per line.
    local cfg
    cfg=$(Store_config_file)
    [ -f "$cfg" ] || { echo "FAIL Get_config_array: no config at $cfg" 1>&2; return 1; }
    python3 -c '
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except (ValueError, OSError) as e:
    sys.stderr.write("FAIL Get_config_array: corrupt config %s: %s\n" % (sys.argv[1], e))
    sys.exit(1)
for x in d.get(sys.argv[2], []):
    print(x)
' "$cfg" "$1"
}

Config_participants()
{
    Get_config_array participants
}

Config_routine_allowlist()
{
    Get_config_array routine_allowlist
}

Is_routine_category()
{
    # Return 0 iff subject $1 matches a routine allowlist category. A category
    # matches when ALL of its whitespace-separated keywords appear (case-
    # insensitively) in the subject, so "low disk space" matches "disk space
    # low on m4" but not "the disk looks fine". Return 2 on a config error so
    # callers can distinguish "not routine" (1) from "could not decide" (2).
    local subject=$1 cfg
    cfg=$(Store_config_file)
    [ -f "$cfg" ] || { echo "FAIL Is_routine_category: no config at $cfg" 1>&2; return 2; }
    python3 -c '
import json, re, sys
cfg, subject = sys.argv[1], sys.argv[2].lower()
try:
    allow = json.load(open(cfg)).get("routine_allowlist", [])
except (ValueError, OSError) as e:
    sys.stderr.write("FAIL Is_routine_category: corrupt config %s: %s\n" % (cfg, e))
    sys.exit(2)
def whole_word_present(keyword):
    return re.search(r"\b" + re.escape(keyword) + r"\b", subject) is not None
for cat in allow:
    keywords = cat.lower().split()
    if keywords and all(whole_word_present(k) for k in keywords):
        sys.exit(0)
sys.exit(1)
' "$cfg" "$subject"
}
