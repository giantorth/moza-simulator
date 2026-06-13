#!/usr/bin/env bash
# Tear down MOZA gadget-rig gadgets created by setup_rig.sh.
#
#   sudo bash sim/teardown_rig.sh                # tear down every moza_* rig gadget
#   sudo bash sim/teardown_rig.sh csp mbooster   # tear down only the named ones
#
# Leaves the legacy single-gadget trees (moza, moza_ab9 from the standalone
# setup scripts) and the kernel modules alone — use their own teardown scripts.
# usbipd is left running if any MOZA gadget remains.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=gadget_common.sh
source "$DIR/gadget_common.sh"

gc_require_root

declare -a KEYS=()
if [[ $# -ge 1 ]]; then
    KEYS=("$@")
else
    # All moza_<key> rig gadgets (exclude the legacy 'moza' and 'moza_ab9' trees,
    # which have their own teardown scripts).
    for g in "$GC_CONFIGFS"/moza_*; do
        [[ -d "$g" ]] || continue
        base=$(basename "$g")             # moza_<key>
        key=${base#moza_}
        [[ "$key" == "ab9" ]] && continue
        KEYS+=("$key")
    done
fi

if [[ ${#KEYS[@]} -eq 0 ]]; then
    echo "No rig gadgets to tear down."
    exit 0
fi

for key in "${KEYS[@]}"; do
    # Kill any engine driving this gadget's port before unbinding the UDC, so a
    # stale ttyGS fd doesn't EBUSY the unbind.
    pkill -f "gadget_manager.py run ${key} " 2>/dev/null || true
    pkill -f "wheel_sim.py --model ${key} " 2>/dev/null || true
    echo "Tearing down moza_${key}..."
    gc_teardown_gadget "$key"
done

# Stop usbipd only if no MOZA gadget (rig or legacy) remains bound.
if ! gc_any_gadget_up; then
    echo "No MOZA gadgets remain — stopping usbipd."
    pkill -x usbipd 2>/dev/null || true
fi

echo "Done."
