"""MOZA Universal Hub bridge — presents merged input sources (ESP32 over UDP,
SDL2 joysticks, Linux evdev) as a KS Pro wheel behind an emulated Universal Hub.

The hub is a userspace USB/IP device (usbip.py), so the bridge runs on Windows
and Linux alike: Windows attaches it with usbip-win2, Linux (and Wine on Linux)
with `usbip attach`. The CDC serial interface is served by wheel_sim.py
(`--model kspro_uhub`) over a localhost socket; the HID joystick interface is
built here from the merged input state.

Entry point: sim/hub_bridge.py. Docs: docs/hub-bridge.md.
"""
