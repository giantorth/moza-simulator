#!/usr/bin/env python3
"""Test XTEA-based trailer algorithms against known (reply, trailer) pairs.

Known data points (from latestcaps/pithouse-switch-list-delete-upload-reupload.pcapng):

  Reply 1 (type=0x01 ready-ack):
    md5 = a6f0ff161012456174ef5060ffd68492
    bytes_written = 0
    total_size    = 1902    (= 0x076e)
    trailer       = 93 71 e8 bd

  Reply 2 (type=0x11 done-ack):
    md5 = (same)
    bytes_written = 1902
    total_size    = 1902
    trailer       = fa cd 10 c6

Key (extracted from MOZA Pit House.exe .rdata at 0x1ccae24):
    "Gudsen.88888888" (15 ASCII + NUL)
"""
import struct


def xtea_encrypt(v0, v1, key, rounds=16):
    """Standard XTEA encrypt, 32 rounds per full TEA spec — but crypt.dll
    uses 16 rounds per block based on the disassembly. Key is 4 u32."""
    mask = 0xFFFFFFFF
    delta = 0x9E3779B9
    total = 0
    for _ in range(rounds):
        v0 = (v0 + (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (total + key[total & 3])) & mask
        total = (total + delta) & mask
        v1 = (v1 + (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (total + key[(total >> 11) & 3])) & mask
    return v0, v1


def tea_encrypt_inline(v0, v1, key, rounds=16):
    """Match the encrypt block at 0x13b9470 in pithouse.exe:
        sum=0; for 16 rounds:
          edx = ((v1<<4) ^ (v1>>5)) + v1        [note: ADD v1, not XOR]
          esi = sum + key[sum & 3]
          edx = edx XOR esi
          v0 += edx
          (same for v1 updating from v0, then sum += delta — WAIT, delta add
          order matters. Let me re-read.)"""
    # From disasm:
    # sum=0, v0, v1 loaded from in[0], in[1]
    # Loop 16 times:
    #   edx = ((v1<<4) ^ (v1>>5)) + v1
    #   idx = sum & 3
    #   esi = sum + key[idx]
    #   edx ^= esi
    #   v0 += edx
    #   (then for the second half)
    #   edx = ((v0<<4) ^ (v0>>5)) + v0
    #   idx = (sum>>11) & 3
    #   ecx = sum + key[idx]
    #   edx ^= ecx
    #   v1 += edx
    #   sum -= 0x61c88647  (i.e. sum += 0x9E3779B9)
    mask = 0xFFFFFFFF
    delta = 0x9E3779B9
    total = 0
    for _ in range(rounds):
        # First half
        tmp = (((v1 << 4) & mask) ^ (v1 >> 5)) + v1
        tmp &= mask
        tmp ^= (total + key[total & 3]) & mask
        v0 = (v0 + tmp) & mask
        # sum update placement: in crypt.dll Tea_Encrypt the `sub 0x61c88647`
        # happens BETWEEN the two halves. Reconstruct accordingly.
        total = (total + delta) & mask
        # Second half
        tmp = (((v0 << 4) & mask) ^ (v0 >> 5)) + v0
        tmp &= mask
        tmp ^= (total + key[(total >> 11) & 3]) & mask
        v1 = (v1 + tmp) & mask
    return v0, v1


def xtea_std(v0, v1, key, rounds=32):
    """Standard Wikipedia XTEA for reference."""
    mask = 0xFFFFFFFF
    delta = 0x9E3779B9
    total = 0
    for _ in range(rounds):
        v0 = (v0 + ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (total + key[total & 3]))) & mask
        total = (total + delta) & mask
        v1 = (v1 + ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (total + key[(total >> 11) & 3]))) & mask
    return v0, v1


KEY_STR = b'Gudsen.88888888\x00'
KEY = struct.unpack('<IIII', KEY_STR)
print('Key u32s:', [hex(k) for k in KEY])

md5 = bytes.fromhex('a6f0ff161012456174ef5060ffd68492')

cases = [
    ('0x01 ready', 0, 1902, bytes.fromhex('9371e8bd')),
    ('0x11 done',  1902, 1902, bytes.fromhex('facd10c6')),
]

# Candidate plaintexts to feed XTEA:
def build_candidates(md5, bw, sz):
    pts = {}
    pts['md5[0:8]']   = md5[:8]
    pts['md5[8:16]']  = md5[8:]
    pts['md5[0:4]|sz_be']  = md5[:4] + sz.to_bytes(4, 'big')
    pts['md5[0:4]|sz_le']  = md5[:4] + sz.to_bytes(4, 'little')
    pts['sz_be|md5[12:16]'] = sz.to_bytes(4, 'big') + md5[12:]
    pts['bw_be|sz_be']     = bw.to_bytes(4, 'big') + sz.to_bytes(4, 'big')
    pts['bw_le|sz_le']     = bw.to_bytes(4, 'little') + sz.to_bytes(4, 'little')
    pts['md5_xor_fold']    = bytes(a^b for a,b in zip(md5[:8], md5[8:]))
    pts['md5[0:4]|bw_be']  = md5[:4] + bw.to_bytes(4, 'big')
    pts['md5[0:4]|0']      = md5[:4] + b'\x00\x00\x00\x00'
    pts['0|md5[0:4]']      = b'\x00\x00\x00\x00' + md5[:4]
    pts['sz_be|bw_be']     = sz.to_bytes(4, 'big') + bw.to_bytes(4, 'big')
    return pts


impls = [('xtea16_inline', lambda v0,v1: tea_encrypt_inline(v0,v1,KEY,16)),
         ('xtea32_std',    lambda v0,v1: xtea_std(v0,v1,KEY,32)),
         ('xtea16_std',    lambda v0,v1: xtea_std(v0,v1,KEY,16))]

for name, impl in impls:
    print(f'\n=== {name} ===')
    matches = 0
    for label, bw, sz, expected_tr in cases:
        pts = build_candidates(md5, bw, sz)
        for pname, pt in pts.items():
            v0, v1 = struct.unpack('<II', pt)
            o0, o1 = impl(v0, v1)
            out = struct.pack('<II', o0, o1)
            for slice_name, tr_test in [('out[0:4]', out[:4]), ('out[4:8]', out[4:]),
                                         ('out[0:4]BE', out[:4][::-1]),
                                         ('out[4:8]BE', out[4:][::-1]),
                                         ('out[0:4]^[4:8]', bytes(a^b for a,b in zip(out[:4], out[4:])))]:
                if tr_test == expected_tr:
                    print(f'  MATCH {label}: pt={pname}({pt.hex()}) {slice_name}={tr_test.hex()}')
                    matches += 1
    print(f'  -> {matches} matches')
