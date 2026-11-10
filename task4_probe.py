"""Timestamped UDP measurement helper used inside the Mininet host namespaces."""
import argparse
import json
import socket
import struct
import time
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("mode", choices=["send", "receive"])
parser.add_argument("--output", required=True)
parser.add_argument("--start", type=float, required=True)
parser.add_argument("--duration", type=float, required=True)
parser.add_argument("--target", default="10.0.0.6")
parser.add_argument("--ready")
args = parser.parse_args()
end = args.start + args.duration
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
with open(args.output, "w", buffering=1) as handle:
    if args.mode == "receive":
        sock.bind(("0.0.0.0", 5001))
        sock.settimeout(0.25)
        Path(args.ready).touch()
        while time.monotonic() < end + 2:
            try:
                data, address = sock.recvfrom(65535)
            except socket.timeout:
                continue
            received = time.monotonic()
            if len(data) < 12:
                continue
            seq, sent = struct.unpack("!Id", data[:12])
            handle.write(json.dumps(dict(seq=seq, sent_time=sent, time=received,
                                         bytes=len(data), source=address[0])) + "\n")
    else:
        # 32 datagrams/s * 1200 bytes * 8 = 0.3072 Mbit/s offered payload.
        # This plus ordinary pings stays below the detector's 50 pps floor.
        sequence = 0
        deadline = args.start
        while deadline < end:
            time.sleep(max(0, deadline - time.monotonic()))
            stamp = time.monotonic()
            payload = struct.pack("!Id", sequence, stamp) + bytes(1188)
            error = None
            try:
                sock.sendto(payload, (args.target, 5001))
            except OSError as exc:
                error = str(exc)
            handle.write(json.dumps(dict(seq=sequence, time=stamp, bytes=len(payload),
                                         error=error)) + "\n")
            sequence += 1
            deadline = args.start + sequence / 32.0
sock.close()

