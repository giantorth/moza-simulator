"""kspro_uhub — KS Pro wheel attached to a MOZA Universal Hub (no wheelbase).

Topology verified from usb-capture/ksp/mozahubstartup.pcapng: the host
enumerates only the hub (VID 0x346E PID 0x0020, a CDC + 2x HID composite), and
on its serial bus only two devices answer — the hub on 0x12 (replies as 0x21)
and the KS Pro on 0x17 (replies as 0x71). PitHouse never addresses 0x13 (no
wheelbase) and gets no answer from 0x14/0x15/0x19-0x1E.

The wheel/display definition is the `kspro` profile verbatim (identity, session
layout, factory dashboards, 7c:23 pages). Only the bus around it changes:
  - no `base_identity` (0x13) and no `pedal_identity` (0x19)
  - a `uhub` block on 0x12 carrying the hub's own identity cascade, the group
    0x64 port-state answers and its group 0x0E parameter table
  - USB gadget PID 0x0020 with a HID joystick function (driven by
    sim/hub_bridge.py, not by wheel_sim)

Hub identity values are byte-exact from the capture (re-derive with
tools/extract_uhub_tables.py). MCU id (group 0x06) and serials (group 0x10) are
redacted placeholders, matching every other profile.
"""
import copy

from ..schema import DeviceBlock, DeviceProfile, GadgetSpec, DEV_HUB, PID_HUB
from . import kspro as _kspro

HUB_IDENTITY = {
    'name': 'S03 HUB',
    'hw_version': 'RS21-S03-HW HUB-',
    'hw_sub': 'CU-V04',
    'sw_version': 'RS21-S03-MC HUB',
    'serial0': 'UHUB000000000000',
    'serial1': 'UHUB000000000001',
    'hw_id': bytes(12),
    'caps': bytes([0x01, 0x02, 0x33, 0x00]),
    'dev_type': bytes([0x01, 0x02, 0x05, 0x08]),
    'identity_09': bytes([0x00, 0x03]),
}

# Group 0x64 hub port-state reads: request `01 <port> 00` -> response. Byte-exact
# from the capture (KS Pro on the hub's wheel port, nothing else attached). Port
# semantics are not decoded yet — served verbatim.
HUB_PORT_STATES = {
    bytes.fromhex('010100'): bytes.fromhex('010502'),
    bytes.fromhex('010200'): bytes.fromhex('010400'),
    bytes.fromhex('010300'): bytes.fromhex('010300'),
    bytes.fromhex('010400'): bytes.fromhex('010207'),
    bytes.fromhex('010500'): bytes.fromhex('010100'),
    # Group 0x64 status polls (sub-cmds 02..08) — not present in the KS Pro
    # capture; taken from a separate Universal Hub capture with an FSR wheel
    # attached ("Disconnection issue.pcapng", not in repo), where the SimHub
    # plugin polls them. 02/04/05 were constant; 03/06/07/08 vary per poll
    # (sensor-like) — the most frequent observed value is served. Without
    # these the generic _PROBE_SYNTH hub echo would answer with the request.
    bytes.fromhex('020000'): bytes.fromhex('0203e8'),
    bytes.fromhex('030000'): bytes.fromhex('030148'),
    bytes.fromhex('040000'): bytes.fromhex('0403e8'),
    bytes.fromhex('050100'): bytes.fromhex('0503e8'),
    bytes.fromhex('060000'): bytes.fromhex('060088'),
    bytes.fromhex('070000'): bytes.fromhex('07001a'),
    bytes.fromhex('080000'): bytes.fromhex('080017'),
}

LEGACY = copy.deepcopy(_kspro.LEGACY)
LEGACY.pop('base_identity')
LEGACY.pop('pedal_identity')
LEGACY['friendly'] = 'KS Pro (Universal Hub)'
# Wheel replay only — the kspro hub/base/pedal tables come from an R12-base
# capture and would answer for devices that don't exist behind a Universal Hub.
LEGACY['replay_tables'] = ['sim/replay/kspro_wheel_17.json']
# Committed extract of catalog_pcapng (tools/extract_catalog_json.py) — used
# when the capture itself is absent (fresh clone / Windows), instead of the
# synthesised catalog, which differs substantially from the real KS Pro one.
LEGACY['catalog_json'] = 'sim/replay/kspro_catalog.json'
LEGACY['hub_identity'] = HUB_IDENTITY
LEGACY['hub_port_states'] = HUB_PORT_STATES

PROFILE = DeviceProfile.from_legacy('kspro_uhub', LEGACY)
PROFILE.blocks[0].extras['_7c23_payloads'] = list(
    _kspro.PROFILE.blocks[0].extras['_7c23_payloads'])
PROFILE.blocks.append(DeviceBlock(
    role='uhub', address=DEV_HUB, ident=HUB_IDENTITY,
    extras={'param_0e_table': 'sim/replay/param_0e_uhub_dev12.json'}))
PROFILE.gadgets = [GadgetSpec(
    pid=PID_HUB, product_str='MOZA Universal Hub',
    functions=('acm', 'hid'), engine='uhub')]
