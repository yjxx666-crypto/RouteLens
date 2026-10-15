import contextlib
import io
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import unittest
from traffic import Aggregator, decode_packet


def ipv4(src="192.168.1.2", dst="8.8.8.8", protocol=6, payload=b""):
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0, 64, protocol, 0,
                       socket.inet_aton(src), socket.inet_aton(dst)) + payload


def ethernet(packet, kind=0x0800):
    return b"\0" * 12 + struct.pack("!H", kind) + packet


class HeaderTests(unittest.TestCase):
    def test_ipv4_vlan_fragments_and_truncated_payload(self):
        packet = ethernet(ipv4(payload=b"x" * 100))
        self.assertEqual(decode_packet(packet[:40], 1), ("192.168.1.2", "8.8.8.8", "TCP"))
        vlan = b"\0" * 12 + struct.pack("!HHHHH", 0x88A8, 1, 0x8100, 2, 0x0800) + ipv4(protocol=17)
        self.assertEqual(decode_packet(vlan, 1)[2], "UDP")
        self.assertIsNone(decode_packet(packet[:25], 1))
        self.assertIsNone(decode_packet(ethernet(b"\0" * 30, 0x0806), 1))
        self.assertEqual(decode_packet(ipv4(), 101)[1], "8.8.8.8")
        offloaded = bytearray(packet)
        offloaded[16:18] = b"\0\0"
        self.assertEqual(decode_packet(offloaded[:40], 1)[1], "8.8.8.8")

    def test_ipv6_extension_and_cooked(self):
        header = struct.pack("!IHBB16s16s", 6 << 28, 8, 0, 64, socket.inet_pton(socket.AF_INET6, "2001:4860::1"), socket.inet_pton(socket.AF_INET6, "2606:4700::1111"))
        extension = bytes([17, 0]) + b"\0" * 6
        self.assertEqual(decode_packet(ethernet(header + extension, 0x86DD), 1), ("2001:4860::1", "2606:4700::1111", "UDP"))
        cooked = b"\0" * 14 + b"\x08\x00" + ipv4()
        self.assertEqual(decode_packet(cooked, 113)[0], "192.168.1.2")
        with self.assertRaises(ValueError):
            decode_packet(b"x" * 50, 999)

    def test_direction_bytes_and_no_retransmission_dedup(self):
        aggregate = Aggregator("outgoing", ["192.168.1.2"])
        packet = ethernet(ipv4())
        for timestamp in (10, 11):
            aggregate.add(packet, 1, 1500, timestamp, 128)
        aggregate.add(ethernet(ipv4(src="8.8.8.8", dst="192.168.1.2")), 1, 60, 12, 60)
        self.assertEqual(aggregate.totals["packets"], 2)
        self.assertEqual(aggregate.totals["bytes"], 3000)
        self.assertEqual(aggregate.totals["ignoredPackets"], 1)
        self.assertEqual(aggregate.totals["truncatedPackets"], 2)
        self.assertEqual(aggregate.flows["8.8.8.8"]["lastSeen"], 11)


@unittest.skipUnless(os.name == "nt" and Path("C:/Windows/System32/Npcap/wpcap.dll").exists(), "requires Npcap")
class FileTests(unittest.TestCase):
    def analyze(self, path, *options):
        result = subprocess.run([sys.executable, str(Path(__file__).with_name("traffic.py")), "offline", "--file", str(path), *options], capture_output=True, text=True, encoding="utf-8", timeout=10)
        events = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(result.returncode, 0, events)
        return [event for event in events if event["event"] == "batch"][-1]

    def test_pcap_and_pcapng_equivalent(self):
        frames = [ethernet(ipv4()), ethernet(ipv4(src="8.8.8.8", dst="192.168.1.2"))]
        with tempfile.TemporaryDirectory() as directory:
            pcap = Path(directory) / "test.pcap"
            pcap.write_bytes(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 128, 1) + b"".join(struct.pack("<IIII", 10 + i, 0, len(frame), 1500) + frame for i, frame in enumerate(frames)))
            def block(kind, body):
                size = len(body) + 12
                return struct.pack("<II", kind, size) + body + struct.pack("<I", size)
            content = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
            content += block(1, struct.pack("<HHI", 1, 0, 128))
            for i, frame in enumerate(frames):
                content += block(6, struct.pack("<IIIII", 0, 0, (10 + i) * 1000000, len(frame), 1500) + frame + b"\0" * ((-len(frame)) % 4))
            pcapng = Path(directory) / "test.pcapng"
            pcapng.write_bytes(content)
            a, b = self.analyze(pcap), self.analyze(pcapng)
            self.assertEqual(a["totals"], b["totals"])
            self.assertEqual(a["totals"]["packets"], 2)
            outgoing = self.analyze(pcapng, "--scope", "outgoing", "--sources", "192.168.1.2")
            self.assertEqual(outgoing["totals"]["packets"], 1)
            self.assertEqual(outgoing["totals"]["bytes"], 1500)

    def test_corrupt_file_explicit_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.pcap"
            path.write_bytes(b"invalid file" * 5)
            result = subprocess.run([sys.executable, str(Path(__file__).with_name("traffic.py")), "offline", "--file", str(path)], capture_output=True, text=True, encoding="utf-8", timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('"event":"error"', result.stdout)


if __name__ == "__main__":
    unittest.main()
