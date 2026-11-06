// Copy to config.h (git-ignored) and edit.
#pragma once

// ── Wi-Fi ───────────────────────────────────────────────────────────────
#define WIFI_SSID      "your-ssid"
#define WIFI_PASSWORD  "your-password"

// ── Bridge ──────────────────────────────────────────────────────────────
// IP of the PC running sim/hub_bridge.py. Unicast is strongly preferred:
// Wi-Fi broadcast frames are sent at the lowest rate with no link-layer
// retries, so they drop far more often. "" = broadcast 255.255.255.255.
#define BRIDGE_HOST    "192.168.1.10"
#define BRIDGE_PORT    34200

// ── Buttons ─────────────────────────────────────────────────────────────
// One GPIO per button, wired to GND (internal pull-up, active low). Entry i
// is sent as button bit i; the bridge maps it onto KS Pro buttons (identity
// by default, or "button_offset"/"buttons" per device in the bridge config).
// Avoid strapping pins (0, 2, 12, 15) and input-only pins without pull-ups
// (34-39) on a classic ESP32.
static const int BUTTON_PINS[] = {13, 14, 16, 17, 18, 19, 21, 22, 23, 25, 26, 27, 32, 33};

// Optional 4-way hat (D-pad), active low. -1 to disable.
#define HAT_UP_PIN     -1
#define HAT_RIGHT_PIN  -1
#define HAT_DOWN_PIN   -1
#define HAT_LEFT_PIN   -1

// Optional analog axes (e.g. clutch paddles on ADC1 pins 34-39). Entry i is
// sent as axis i, scaled 0..65535. Keep the trailing -1 (end marker), e.g.
// {34, 35, -1}; {-1} = no axes.
static const int AXIS_PINS[] = {-1};

// ── Timing ──────────────────────────────────────────────────────────────
#define DEBOUNCE_MS    5     // a button must be stable this long to change state
#define HEARTBEAT_MS   50    // full-state resend interval (bridge drops us after 500 ms)
#define AXIS_DEADBAND  64    // ignore axis jitter smaller than this (0..65535 scale)
