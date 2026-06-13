#!/usr/bin/env bash
# Shared CDC-ACM USB-gadget helpers for the MOZA simulator rig.
#
# Sourced by setup_rig.sh / teardown_rig.sh / status_rig.sh. Factors the
# configfs + dummy_hcd + usbipd logic that setup_usbip_gadget.sh and
# setup_ab9_gadget.sh each implemented separately, generalised to N coexisting
# gadgets (free-UDC selection, port_num-based ttyGS discovery, idempotent
# usbipd, PID-keyed enumeration). Every gadget lives at
# /sys/kernel/config/usb_gadget/moza_<key>.
#
# All functions require root (configfs writes). Source, don't execute.

GC_CONFIGFS=/sys/kernel/config/usb_gadget
GC_VID=0x346E

gc_require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "Must run as root (configfs + usbipd)." >&2
        exit 1
    fi
}

# gc_count_udcs -> number of dummy_udc.N slots currently present
gc_count_udcs() {
    ls /sys/class/udc/ 2>/dev/null | grep -cE '^dummy' || true
}

# gc_any_gadget_up -> 0 (true) if any moza_* gadget is bound to a UDC
gc_any_gadget_up() {
    local g
    for g in "$GC_CONFIGFS"/moza_*/UDC "$GC_CONFIGFS"/moza/UDC; do
        [[ -f "$g" ]] || continue
        [[ -n "$(cat "$g" 2>/dev/null | tr -d '[:space:]')" ]] && return 0
    done
    return 1
}

# gc_load_modules — modprobe dummy_hcd + libcomposite, mount configfs.
gc_load_modules() {
    modprobe dummy_hcd 2>/dev/null || modprobe dummy_hcd
    modprobe libcomposite
    mountpoint -q /sys/kernel/config || mount -t configfs none /sys/kernel/config
}

# gc_ensure_udcs <n> — guarantee at least <n> dummy UDC slots. dummy_hcd
# defaults to 2; raising the count needs a module reload, which drops ALL
# gadgets — so this MUST run before any gadget in the rig is brought up, and it
# refuses if one is already live (the caller sizes N for the whole rig up front).
gc_ensure_udcs() {
    local need="$1" have
    gc_load_modules
    have=$(gc_count_udcs)
    if (( have >= need )); then
        return 0
    fi
    if gc_any_gadget_up; then
        echo "Need $need dummy UDC slots but only $have exist, and a gadget is" >&2
        echo "already up. Raising the UDC count requires reloading dummy_hcd," >&2
        echo "which drops every gadget. Tear the rig down first (teardown_rig.sh)." >&2
        return 1
    fi
    echo "Raising dummy_hcd UDC count $have -> $need (module reload)..."
    rmmod dummy_hcd 2>/dev/null || true
    modprobe dummy_hcd num="$need"
    have=$(gc_count_udcs)
    if (( have < need )); then
        echo "dummy_hcd still has only $have UDC slots after num=$need reload." >&2
        return 1
    fi
}

# gc_find_free_udc -> echo a dummy_udc.N not claimed by any configfs gadget
gc_find_free_udc() {
    local candidate g in_use
    for candidate in $(ls /sys/class/udc/ 2>/dev/null | grep -E '^dummy' || true); do
        in_use=0
        for g in "$GC_CONFIGFS"/*/UDC; do
            [[ -f "$g" ]] || continue
            if [[ "$(cat "$g" 2>/dev/null | tr -d '[:space:]')" == "$candidate" ]]; then
                in_use=1; break
            fi
        done
        if (( in_use == 0 )); then
            echo "$candidate"; return 0
        fi
    done
    return 1
}

# gc_create_gadget <key> <pid_hex> <product> <serial> <maxpower> <iad:0|1>
#   Builds the configfs tree, binds a free UDC, and echoes the allocated
#   /dev/ttyGS<N> path on success. iad=1 sets the IAD composite class bytes
#   (AB9 mirrors its real descriptor this way).
gc_create_gadget() {
    local key="$1" pid="$2" product="$3" serial="$4" maxpower="$5" iad="${6:-0}"
    local gadget="$GC_CONFIGFS/moza_${key}"

    mkdir -p "$gadget"
    echo "$GC_VID" > "$gadget/idVendor"
    echo "$pid"    > "$gadget/idProduct"
    echo 0x0100    > "$gadget/bcdDevice"
    echo 0x0200    > "$gadget/bcdUSB"
    if [[ "$iad" == "1" ]]; then
        echo 0xEF > "$gadget/bDeviceClass"
        echo 0x02 > "$gadget/bDeviceSubClass"
        echo 0x01 > "$gadget/bDeviceProtocol"
    fi

    mkdir -p "$gadget/strings/0x409"
    echo "MOZA Racing" > "$gadget/strings/0x409/manufacturer"
    echo "$product"    > "$gadget/strings/0x409/product"
    echo "$serial"     > "$gadget/strings/0x409/serialnumber"

    mkdir -p "$gadget/configs/c.1/strings/0x409"
    echo "Config 1"  > "$gadget/configs/c.1/strings/0x409/configuration"
    echo "$maxpower" > "$gadget/configs/c.1/MaxPower"

    mkdir -p "$gadget/functions/acm.usb0"
    ln -sf "$gadget/functions/acm.usb0" "$gadget/configs/c.1/"

    local udc
    udc=$(gc_find_free_udc) || {
        echo "No free dummy UDC for moza_${key}. Raise the count:" >&2
        echo "    rmmod dummy_hcd && modprobe dummy_hcd num=N" >&2
        return 1
    }
    if ! timeout 5 sh -c 'echo "$1" > "$2/UDC"' _ "$udc" "$gadget"; then
        echo "UDC bind timed out for moza_${key} — dummy_hcd/libcomposite wedged." >&2
        return 1
    fi

    local port_num ttygs
    port_num=$(cat "$gadget/functions/acm.usb0/port_num" 2>/dev/null || true)
    if [[ -z "$port_num" ]]; then
        echo "Could not read port_num for moza_${key}/acm.usb0." >&2
        return 1
    fi
    ttygs=/dev/ttyGS${port_num}
    local _
    for _ in 1 2 3 4 5; do
        [[ -c "$ttygs" ]] && break
        sleep 0.2
    done
    chmod a+rw "$ttygs" 2>/dev/null || true
    echo "$ttygs"
}

# gc_start_usbipd — start usbipd if not already listening on 3240 (idempotent;
# never restart, that drops coexisting gadget exports).
gc_start_usbipd() {
    command -v usbipd >/dev/null || {
        echo "usbipd not installed — pacman -S usbip / apt install linux-tools-generic." >&2
        return 1
    }
    if pgrep -x usbipd >/dev/null; then
        return 0
    fi
    usbipd -D
    local _
    for _ in $(seq 1 10); do
        ss -tlnp 2>/dev/null | grep -q ':3240 ' && return 0
        sleep 0.3
    done
    ss -tlnp 2>/dev/null | grep -q ':3240 ' || {
        echo "usbipd not listening on port 3240 after 3s." >&2
        return 1
    }
}

# gc_wait_enumerate <pid_hex> [<serial>] -> echo the dummy_hcd busid.
# When <serial> is given, also match the device serialnumber — required to
# disambiguate multiple same-PID gadgets (the canonical 3× mBooster layout all
# share PID 0x0008).
gc_wait_enumerate() {
    local pid_lc; pid_lc=$(printf '%04x' "$1")
    local want_serial="${2:-}"
    local d real attempt dser
    for attempt in $(seq 1 20); do
        for d in /sys/bus/usb/devices/*-*; do
            [[ -e "$d/idVendor" ]] || continue
            real=$(readlink -f "$d" 2>/dev/null) || continue
            [[ "$real" == *dummy_hcd* ]] || continue
            [[ "$(cat "$d/idVendor")" == "346e" ]] || continue
            [[ "$(cat "$d/idProduct")" == "$pid_lc" ]] || continue
            if [[ -n "$want_serial" ]]; then
                dser=$(cat "$d/serial" 2>/dev/null || true)
                [[ "$dser" == "$want_serial" ]] || continue
            fi
            basename "$d"; return 0
        done
        sleep 0.3
    done
    return 1
}

# gc_usbip_bind <busid> — bind to usbip-host with the cdc_acm interface-reprobe
# retry both single-gadget scripts use.
gc_usbip_bind() {
    local busid="$1" iface
    usbip bind -b "$busid" 2>/dev/null || true
    sleep 0.3
    usbip list -r 127.0.0.1 2>/dev/null | grep -q "$busid" && return 0
    usbip unbind -b "$busid" 2>/dev/null || true
    for iface in /sys/bus/usb/devices/"$busid":*; do
        echo "$(basename "$iface")" > /sys/bus/usb/drivers_probe 2>/dev/null || true
    done
    sleep 0.3
    usbip bind -b "$busid" 2>/dev/null || true
    sleep 0.3
    usbip list -r 127.0.0.1 2>/dev/null | grep -q "$busid"
}

# gc_teardown_gadget <key> — unbind UDC, remove the configfs tree. Safe if the
# gadget doesn't exist.
gc_teardown_gadget() {
    local key="$1" gadget="$GC_CONFIGFS/moza_${key}"
    [[ -d "$gadget" ]] || return 0
    local busid
    busid=$(gc_wait_enumerate_fast "$(cat "$gadget/idProduct" 2>/dev/null)")
    [[ -n "$busid" ]] && usbip unbind -b "$busid" 2>/dev/null || true
    echo "" > "$gadget/UDC" 2>/dev/null || true
    local f
    for f in "$gadget"/configs/c.1/acm.usb0; do
        [[ -e "$f" ]] && rm -f "$f"
    done
    rmdir "$gadget"/configs/c.1/strings/0x409 2>/dev/null || true
    rmdir "$gadget"/configs/c.1 2>/dev/null || true
    rmdir "$gadget"/functions/acm.usb0 2>/dev/null || true
    rmdir "$gadget"/strings/0x409 2>/dev/null || true
    rmdir "$gadget" 2>/dev/null || true
}

# gc_wait_enumerate_fast <pid_hex> — single-pass busid lookup (no retry loop),
# used by teardown where the device may already be gone.
gc_wait_enumerate_fast() {
    [[ -n "${1:-}" ]] || return 0
    local pid_lc; pid_lc=$(printf '%04x' "0x$1" 2>/dev/null || printf '%04x' "$1")
    local d real
    for d in /sys/bus/usb/devices/*-*; do
        [[ -e "$d/idVendor" ]] || continue
        real=$(readlink -f "$d" 2>/dev/null) || continue
        if [[ "$real" == *dummy_hcd* ]] \
           && [[ "$(cat "$d/idVendor")" == "346e" ]] \
           && [[ "$(cat "$d/idProduct")" == "$pid_lc" ]]; then
            basename "$d"; return 0
        fi
    done
    return 0
}
