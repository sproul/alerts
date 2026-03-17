#!/bin/bash
set -o pipefail
. $dp/git/maturin/util/python.inc
args='--clear-seen --debug'
debug_mode=''
dry_mode=''
t=`mktemp`; trap "rm $t*" EXIT
verbose_mode=''
while (( $# >= 1 )); do
        case "$1" in
                -dry)
                        dry_mode=-dry
                ;;
                -q|-quiet)
                        verbose_mode=''
                ;;
                -raw)
                        args=''
                ;;
                -v|-verbose)
                        verbose_mode=-v
                ;;
                -x)
                        set -x
                        debug_mode=-x
                ;;
                *)
                        break
                ;;
        esac
        shift
done

python3 $dp/git/alerts/alert__gmail_check_important_senders.py $args $*
exit
bx $dp/git/alerts/g.sh -raw --clear-seen
exit
$dp/git/alerts/g.sh