// ESP32 wireless button box -> MOZA Universal Hub bridge (sim/hub_bridge.py).
//
// Sends the bridge's UDP "MZBR" v1 packet (see sim/uhub/sources/udp.py): every
// packet is the FULL button/hat/axis state, sent immediately on any change and
// every HEARTBEAT_MS otherwise. The bridge releases our buttons if it hears
// nothing for 500 ms, so a Wi-Fi drop can never leave a button held.

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <esp_random.h>

#if __has_include("config.h")
#include "config.h"
#else
#error "Copy include/config.example.h to include/config.h and edit it."
#endif

#define COUNT_OF(a) (sizeof(a) / sizeof((a)[0]))

static const size_t NUM_BUTTONS = COUNT_OF(BUTTON_PINS);
static const size_t NUM_AXES = COUNT_OF(AXIS_PINS) - 1;   // trailing -1 end marker
static_assert(NUM_BUTTONS <= 128, "at most 128 buttons");
static_assert(NUM_AXES <= 8, "at most 8 axes");

#pragma pack(push, 1)
struct Packet {                 // little-endian on ESP32, matches udp.HEADER
  char     magic[4];            // "MZBR"
  uint8_t  version;             // 1
  uint8_t  flags;               // 0
  uint8_t  hat;                 // 0-7 N..NW clockwise, 8 = centred
  uint8_t  axis_count;
  uint32_t device_id;
  uint32_t session;
  uint32_t seq;
  uint8_t  buttons[16];
  uint16_t axes[8];             // only axis_count are sent
};
#pragma pack(pop)
static_assert(offsetof(Packet, axes) == 36, "header must be 36 bytes");

static WiFiUDP udp;
static IPAddress bridgeIp;
static Packet pkt;

static bool stable[128];        // debounced state
static bool lastRaw[128];
static uint32_t rawSince[128];
static uint32_t lastSendMs = 0;

static bool pinActive(int pin) { return pin >= 0 && digitalRead(pin) == LOW; }

static uint8_t readHat() {
  const bool u = pinActive(HAT_UP_PIN), r = pinActive(HAT_RIGHT_PIN);
  const bool d = pinActive(HAT_DOWN_PIN), l = pinActive(HAT_LEFT_PIN);
  if (u && r) return 1;
  if (d && r) return 3;
  if (d && l) return 5;
  if (u && l) return 7;
  if (u) return 0;
  if (r) return 2;
  if (d) return 4;
  if (l) return 6;
  return 8;
}

static void connectWifi() {
  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);         // modem sleep adds 100+ ms latency spikes
  WiFi.setAutoReconnect(true);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  Serial.printf("Wi-Fi: connecting to %s", WIFI_SSID);
  while (WiFi.status() != WL_CONNECTED) {
    delay(250);
    Serial.print('.');
  }
  Serial.printf("\nWi-Fi: %s\n", WiFi.localIP().toString().c_str());
}

static void sendState() {
  pkt.seq++;
  udp.beginPacket(bridgeIp, BRIDGE_PORT);
  udp.write(reinterpret_cast<const uint8_t *>(&pkt), 36 + 2 * NUM_AXES);
  udp.endPacket();
  lastSendMs = millis();
}

void setup() {
  Serial.begin(115200);
  for (size_t i = 0; i < NUM_BUTTONS; i++) pinMode(BUTTON_PINS[i], INPUT_PULLUP);
  for (int pin : {HAT_UP_PIN, HAT_RIGHT_PIN, HAT_DOWN_PIN, HAT_LEFT_PIN})
    if (pin >= 0) pinMode(pin, INPUT_PULLUP);
  analogReadResolution(12);

  memcpy(pkt.magic, "MZBR", 4);
  pkt.version = 1;
  pkt.hat = 8;
  pkt.axis_count = NUM_AXES;
  pkt.device_id = static_cast<uint32_t>(ESP.getEfuseMac());   // low 32 bits of MAC
  pkt.session = esp_random();                                  // new per boot
  Serial.printf("device_id=0x%08x session=0x%08x buttons=%u axes=%u\n",
                pkt.device_id, pkt.session, (unsigned)NUM_BUTTONS, (unsigned)NUM_AXES);

  connectWifi();
  if (strlen(BRIDGE_HOST) == 0) bridgeIp = IPAddress(255, 255, 255, 255);
  else if (!bridgeIp.fromString(BRIDGE_HOST)) Serial.println("BRIDGE_HOST is not an IP address");
  udp.begin(0);
}

void loop() {
  const uint32_t now = millis();
  bool changed = false;

  for (size_t i = 0; i < NUM_BUTTONS; i++) {
    const bool raw = digitalRead(BUTTON_PINS[i]) == LOW;
    if (raw != lastRaw[i]) {
      lastRaw[i] = raw;
      rawSince[i] = now;
    } else if (raw != stable[i] && now - rawSince[i] >= DEBOUNCE_MS) {
      stable[i] = raw;
      if (raw) pkt.buttons[i / 8] |= (1u << (i % 8));
      else pkt.buttons[i / 8] &= ~(1u << (i % 8));
      changed = true;
    }
  }

  const uint8_t hat = readHat();
  if (hat != pkt.hat) {
    pkt.hat = hat;
    changed = true;
  }

  for (size_t i = 0; i < NUM_AXES; i++) {
    const uint16_t v = static_cast<uint16_t>(analogRead(AXIS_PINS[i]) * 65535UL / 4095UL);
    if (abs(static_cast<int>(v) - static_cast<int>(pkt.axes[i])) > AXIS_DEADBAND) {
      pkt.axes[i] = v;
      changed = true;
    }
  }

  if (WiFi.status() == WL_CONNECTED && (changed || now - lastSendMs >= HEARTBEAT_MS)) {
    sendState();
  }
  delay(1);
}
