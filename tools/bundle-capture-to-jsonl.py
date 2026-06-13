#!/usr/bin/env python3
"""Convert a plugin diagnostics-bundle serial-capture.txt into the moza-wire
JSONL format the trace tools consume.

Bundle line format:
    2026-05-29 18:30:20.828 R  wheelbase  c3 41 7c 23 ...
  -> dir T = host->base (h2b), R = base->host (b2h)

Usage: tools/bundle-capture-to-jsonl.py serial-capture.txt > out.jsonl
"""
import sys, json, re
from datetime import datetime

LINE = re.compile(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)\s+([TR])\s+\S+\s+([0-9a-fA-F ]+)$')

def main():
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr); sys.exit(2)
    t0 = None
    with open(sys.argv[1]) as fh:
        for line in fh:
            m = LINE.match(line.rstrip('\n'))
            if not m:
                continue
            ts, dr, hexpart = m.groups()
            t = datetime.strptime(ts, '%Y-%m-%d %H:%M:%S.%f').timestamp()
            if t0 is None:
                t0 = t
            hexs = hexpart.replace(' ', '')
            if len(hexs) % 2:
                continue
            print(json.dumps({
                "t": round(t - t0, 6),
                "dir": "h2b" if dr == "T" else "b2h",
                "hex": hexs,
            }))

if __name__ == "__main__":
    main()
