#!/usr/bin/env bash
# Bring up a multi-device MOZA gadget rig: one CDC-ACM gadget per device-profile
# key, with up-front dummy_hcd UDC scaling, then print the per-gadget engine
# command. Generalises setup_usbip_gadget.sh (wheel) + setup_ab9_gadget.sh to N
# coexisting devices.
#
#   sudo bash sim/setup_rig.sh csp mbooster handbrake
#   # then, non-root, one terminal per gadget (commands are printed below):
#   python3 sim/gadget_manager.py run csp /dev/ttyGS0
#   python3 sim/gadget_manager.py run mbooster /dev/ttyGS1
#   python3 sim/gadget_manager.py run handbrake /dev/ttyGS2
#
# Tear down with: sudo bash sim/teardown_rig.sh
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=gadget_common.sh
source "$DIR/gadget_common.sh"

gc_require_root
[[ $# -ge 1 ]] || { echo "usage: setup_rig.sh <profile-key> [<key>...]" >&2; exit 1; }

# Compute the rig spec (UDC need + per-gadget lines) from the Python registry.
SPEC=$(python3 "$DIR/gadget_manager.py" spec "$@") || exit 1
NEED=$(awk -F'\t' '$1=="UDC_NEEDED"{print $2}' <<<"$SPEC")
[[ -n "$NEED" ]] || { echo "could not compute UDC need" >&2; exit 1; }

# Scale dummy_hcd UDC slots up front (a mid-rig reload would drop live gadgets).
gc_ensure_udcs "$NEED" || exit 1
gc_start_usbipd || exit 1

echo "Bringing up $NEED gadget(s)..."
declare -a RUNCMDS=()
while IFS=$'\t' read -r tag gkey key pid product serial maxpower iad engine; do
    [[ "$tag" == "GADGET" ]] || continue
    echo "── moza_${gkey}  (pid=$pid engine=$engine)"
    ttygs=$(gc_create_gadget "$gkey" "$pid" "$product" "$serial" "$maxpower" "$iad") \
        || { echo "create failed for $gkey" >&2; exit 1; }
    busid=$(gc_wait_enumerate "$pid" "$serial") \
        || { echo "gadget moza_${gkey} did not enumerate" >&2; exit 1; }
    gc_usbip_bind "$busid" || { echo "usbip bind failed for $gkey" >&2; exit 1; }
    echo "   ttyGS=$ttygs  busid=$busid"
    RUNCMDS+=("python3 $DIR/gadget_manager.py run $key $ttygs    # busid $busid")
done <<<"$SPEC"

echo
echo "── rig ready — start one engine per gadget (non-root): ──"
for c in "${RUNCMDS[@]}"; do echo "  $c"; done
echo
echo "On Windows, attach each gadget: usbip attach -r <linux-ip> -b <busid>"
echo "Status: bash $DIR/status_rig.sh   |   Teardown: sudo bash $DIR/teardown_rig.sh"
