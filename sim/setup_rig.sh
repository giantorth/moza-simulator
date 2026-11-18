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
#
# Default mode exports each gadget to usbipd for a remote Windows host, so it
# gets no local ttyACM. --local skips usbip: the gadget stays on this machine's
# dummy_hcd bus, cdc_acm / usbhid bind it like real hardware (/dev/ttyACM<N>,
# /dev/hidraw<N>), and a local Wine that maps real USB serial devices (the
# linux-simracing-utils prefix) sees the VID/PID and the HID interface:
#   sudo bash sim/setup_rig.sh --local fcs
# Without root, run the engine on a tty0tty pair instead (CDC only):
#   python3 sim/gadget_manager.py run mbooster /dev/tnt0   # prefix COM -> /dev/tnt1
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=gadget_common.sh
source "$DIR/gadget_common.sh"

LOCAL=0
if [[ "${1:-}" == "--local" ]]; then
    LOCAL=1
    shift
fi

gc_require_root
[[ $# -ge 1 ]] || { echo "usage: setup_rig.sh [--local] <profile-key> [<key>...]" >&2; exit 1; }

# Compute the rig spec (UDC need + per-gadget lines) from the Python registry.
SPEC=$(python3 "$DIR/gadget_manager.py" spec "$@") || exit 1
NEED=$(awk -F'\t' '$1=="UDC_NEEDED"{print $2}' <<<"$SPEC")
[[ -n "$NEED" ]] || { echo "could not compute UDC need" >&2; exit 1; }

# Scale dummy_hcd UDC slots up front (a mid-rig reload would drop live gadgets).
gc_ensure_udcs "$NEED" || exit 1
(( LOCAL )) || gc_start_usbipd || exit 1

# host_nodes <busid> -> "/dev/ttyACMn /dev/hidrawn ..." bound on the host side
host_nodes() {
    local busid="$1" n out=""
    for n in /sys/bus/usb/devices/"$busid":*/tty/* /sys/bus/usb/devices/"$busid":*/*/hidraw/*; do
        [[ -e "$n" ]] && out+=" /dev/$(basename "$n")"
    done
    echo "${out# }"
}

echo "Bringing up $NEED gadget(s)$( (( LOCAL )) && echo ' (local, no usbip)')..."
declare -a RUNCMDS=()
HIDTMP=$(mktemp -d)
trap 'rm -rf "$HIDTMP"' EXIT
while IFS=$'\t' read -r tag gkey key pid product serial maxpower iad engine manufacturer hidlen; do
    [[ "$tag" == "GADGET" ]] || continue
    echo "── moza_${gkey}  (pid=$pid engine=$engine)"
    hiddesc=""
    if (( ${hidlen:-0} > 0 )); then
        hiddesc="$HIDTMP/${gkey}.desc"
        python3 "$DIR/gadget_manager.py" hid-desc "$key" > "$hiddesc" \
            || { echo "no HID descriptor for $key" >&2; exit 1; }
    fi
    ttygs=$(gc_create_gadget "$gkey" "$pid" "$product" "$serial" "$maxpower" "$iad" \
                             "$manufacturer" "${hidlen:-0}" "$hiddesc") \
        || { echo "create failed for $gkey" >&2; exit 1; }
    busid=$(gc_wait_enumerate "$pid" "$serial") \
        || { echo "gadget moza_${gkey} did not enumerate" >&2; exit 1; }
    if (( LOCAL )); then
        nodes=""
        for _ in $(seq 1 15); do
            nodes=$(host_nodes "$busid")
            [[ -n "$nodes" ]] && break
            sleep 0.2
        done
        echo "   ttyGS=$ttygs  busid=$busid  host: ${nodes:-(no driver bound yet)}"
    else
        gc_usbip_bind "$busid" || { echo "usbip bind failed for $gkey" >&2; exit 1; }
        echo "   ttyGS=$ttygs  busid=$busid"
    fi
    if [[ "$gkey" != "$key" && -n "$hiddesc" ]]; then
        # Repeated key: the engine can't derive the gadget from the profile key.
        RUNCMDS+=("FCS_HID_DEV=$(gc_hidg_path "$gkey") python3 $DIR/gadget_manager.py run $key $ttygs    # busid $busid")
    else
        RUNCMDS+=("python3 $DIR/gadget_manager.py run $key $ttygs    # busid $busid")
    fi
done <<<"$SPEC"

echo
echo "── rig ready — start one engine per gadget (non-root): ──"
for c in "${RUNCMDS[@]}"; do echo "  $c"; done
echo
if (( LOCAL )); then
    echo "Local mode: restart the Wine session (wineserver -k) so it picks up the new USB serial port."
else
    echo "On Windows, attach each gadget: usbip attach -r <linux-ip> -b <busid>"
fi
echo "Status: bash $DIR/status_rig.sh   |   Teardown: sudo bash $DIR/teardown_rig.sh"
