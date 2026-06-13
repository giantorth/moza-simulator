#!/usr/bin/env bash
# Show the state of the MOZA gadget rig: every moza* gadget, its PID, bound UDC,
# ttyGS, and usbip export status. Read-only — safe to run without root (some
# fields need root to read).
set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=gadget_common.sh
source "$DIR/gadget_common.sh"

echo "=== dummy_hcd UDC slots ==="
ls /sys/class/udc/ 2>/dev/null | grep -E '^dummy' || echo "  (none — dummy_hcd not loaded)"
echo "  total: $(gc_count_udcs)"

echo
echo "=== usbipd ==="
if pgrep -x usbipd >/dev/null; then
    echo "  running (pid $(pgrep -x usbipd | tr '\n' ' '))"
    ss -tlnp 2>/dev/null | grep -q ':3240 ' && echo "  listening on :3240" || echo "  NOT listening on :3240"
else
    echo "  not running"
fi

echo
echo "=== gadgets ==="
shopt -s nullglob
found=0
for g in "$GC_CONFIGFS"/moza "$GC_CONFIGFS"/moza_*; do
    [[ -d "$g" ]] || continue
    found=1
    name=$(basename "$g")
    pid=$(cat "$g/idProduct" 2>/dev/null || echo "?")
    udc=$(cat "$g/UDC" 2>/dev/null | tr -d '[:space:]')
    port=$(cat "$g/functions/acm.usb0/port_num" 2>/dev/null || echo "?")
    printf "  %-16s pid=%-7s UDC=%-14s ttyGS%s\n" \
        "$name" "$pid" "${udc:-(unbound)}" "$port"
done
[[ $found -eq 0 ]] && echo "  (no moza gadgets)"

echo
echo "=== exportable to remote (usbip) ==="
usbip list -r 127.0.0.1 2>/dev/null | grep -E '346e|Moza|MOZA' || echo "  (none / usbipd down)"
