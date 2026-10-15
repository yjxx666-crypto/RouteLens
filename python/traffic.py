"""Streaming Npcap capture / PCAP reader. Python standard library only.

No packet payload is sent to the UI. Optional recordings use a 128-byte snaplen.
"""
import argparse
import ctypes as C
import ipaddress
import json
import os
import socket
import struct
import sys
import threading
import time
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


def emit(value):
    print(json.dumps(value, ensure_ascii=False, separators=(",", ":")), flush=True)


class Addr(C.Structure):
    pass


Addr._fields_ = [("next", C.POINTER(Addr)), ("addr", C.c_void_p),
                 ("netmask", C.c_void_p), ("broadaddr", C.c_void_p), ("dstaddr", C.c_void_p)]


class Device(C.Structure):
    pass


Device._fields_ = [("next", C.POINTER(Device)), ("name", C.c_char_p),
                   ("description", C.c_char_p), ("addresses", C.POINTER(Addr)), ("flags", C.c_uint)]


class Header(C.Structure):
    _fields_ = [("sec", C.c_long), ("usec", C.c_long), ("caplen", C.c_uint), ("length", C.c_uint)]


class BPF(C.Structure):
    _fields_ = [("length", C.c_uint), ("instructions", C.c_void_p)]


class Stats(C.Structure):
    _fields_ = [("received", C.c_uint), ("dropped", C.c_uint), ("interfaceDropped", C.c_uint), ("captured", C.c_uint)]


class Pcap:
    def __init__(self):
        dll_dir = Path(os.environ.get("WINDIR", "C:/Windows")) / "System32/Npcap"
        if not (dll_dir / "wpcap.dll").exists():
            raise RuntimeError("未找到 Npcap。请安装 Npcap 后重新启动服务。")
        self.dll_handle = os.add_dll_directory(str(dll_dir))
        self.lib = C.CDLL(str(dll_dir / "wpcap.dll"))
        definitions = {
            "pcap_findalldevs": ([C.POINTER(C.POINTER(Device)), C.c_char_p], C.c_int),
            "pcap_freealldevs": ([C.POINTER(Device)], None),
            "pcap_open_live": ([C.c_char_p, C.c_int, C.c_int, C.c_int, C.c_char_p], C.c_void_p),
            "pcap_open_offline": ([C.c_char_p, C.c_char_p], C.c_void_p),
            "pcap_next_ex": ([C.c_void_p, C.POINTER(C.POINTER(Header)), C.POINTER(C.POINTER(C.c_ubyte))], C.c_int),
            "pcap_datalink": ([C.c_void_p], C.c_int), "pcap_close": ([C.c_void_p], None),
            "pcap_geterr": ([C.c_void_p], C.c_char_p),
            "pcap_setnonblock": ([C.c_void_p, C.c_int, C.c_char_p], C.c_int),
            "pcap_compile": ([C.c_void_p, C.POINTER(BPF), C.c_char_p, C.c_int, C.c_uint], C.c_int),
            "pcap_setfilter": ([C.c_void_p, C.POINTER(BPF)], C.c_int),
            "pcap_freecode": ([C.POINTER(BPF)], None),
            "pcap_stats": ([C.c_void_p, C.POINTER(Stats)], C.c_int),
            "pcap_dump_open": ([C.c_void_p, C.c_char_p], C.c_void_p),
            "pcap_dump": ([C.c_void_p, C.POINTER(Header), C.POINTER(C.c_ubyte)], None),
            "pcap_dump_close": ([C.c_void_p], None),
        }
        for name, (args, result) in definitions.items():
            function = getattr(self.lib, name)
            function.argtypes, function.restype = args, result

    def devices(self):
        head = C.POINTER(Device)()
        error = C.create_string_buffer(256)
        if self.lib.pcap_findalldevs(C.byref(head), error):
            raise RuntimeError(error.value.decode(errors="replace"))
        result, current = [], head
        try:
            while current:
                device = current.contents
                addresses, address = [], device.addresses
                while address:
                    ptr = address.contents.addr
                    if ptr:
                        family = C.c_ushort.from_address(ptr).value
                        if family == socket.AF_INET:
                            addresses.append(socket.inet_ntop(socket.AF_INET, C.string_at(ptr + 4, 4)))
                        elif family == socket.AF_INET6:
                            addresses.append(socket.inet_ntop(socket.AF_INET6, C.string_at(ptr + 8, 16)))
                    address = address.contents.next
                result.append({"id": device.name.decode(), "name": (device.description or device.name).decode(errors="replace"),
                               "addresses": addresses, "loopback": bool(device.flags & 1), "up": bool(device.flags & 2),
                               "connected": (device.flags & 0x30) != 0x20})
                current = device.next
        finally:
            self.lib.pcap_freealldevs(head)
        return result


def decode_packet(data, linktype):
    """Extract only network headers. Ignore non-IP / malformed or truncated headers."""
    offset, kind = 0, None
    if linktype == 1:  # Ethernet, including stacked VLAN tags
        if len(data) < 14:
            return None
        offset, kind = 14, struct.unpack_from("!H", data, 12)[0]
        while kind in (0x8100, 0x88A8, 0x9100):
            if len(data) < offset + 4:
                return None
            kind = struct.unpack_from("!H", data, offset + 2)[0]
            offset += 4
    elif linktype in (0, 108):  # BSD NULL / LOOP, byte order differs
        if len(data) < 4:
            return None
        family = int.from_bytes(data[:4], "little" if linktype == 0 else "big")
        kind, offset = (0x0800 if family == 2 else 0x86DD if family in (10, 23, 24, 28, 30) else 0), 4
    elif linktype == 113:  # Linux cooked v1
        if len(data) < 16:
            return None
        kind, offset = struct.unpack_from("!H", data, 14)[0], 16
    elif linktype == 276:  # Linux cooked v2
        if len(data) < 20:
            return None
        kind, offset = struct.unpack_from("!H", data, 0)[0], 20
    elif linktype in (12, 101, 228, 229):  # raw IP
        if not data:
            return None
        kind = 0x0800 if data[0] >> 4 == 4 else 0x86DD
    else:
        raise ValueError(f"不支持的链路类型 {linktype}（支持 Ethernet / VLAN / RAW / NULL / Linux cooked）")
    view = data[offset:]
    if kind == 0x0800 and len(view) >= 20 and view[0] >> 4 == 4:
        ihl = (view[0] & 15) * 4
        # Outbound segmentation offload can leave total-length zero in capture.
        total_length = struct.unpack_from("!H", view, 2)[0]
        if ihl < 20 or len(view) < ihl or (total_length and total_length < ihl):
            return None
        src, dst = socket.inet_ntop(socket.AF_INET, view[12:16]), socket.inet_ntop(socket.AF_INET, view[16:20])
        protocol = view[9]
        return src, dst, {6: "TCP", 17: "UDP", 1: "ICMP"}.get(protocol, f"IP/{protocol}")
    if kind == 0x86DD and len(view) >= 40 and view[0] >> 4 == 6:
        src, dst = socket.inet_ntop(socket.AF_INET6, view[8:24]), socket.inet_ntop(socket.AF_INET6, view[24:40])
        protocol, pos = view[6], 40
        for _ in range(8):
            if protocol not in (0, 43, 44, 51, 60):
                break
            if len(view) < pos + 2:
                return src, dst, "IPv6/extension"
            nxt = view[pos]
            size = 8 if protocol == 44 else (view[pos + 1] + 2) * 4 if protocol == 51 else (view[pos + 1] + 1) * 8
            if size < 8 or len(view) < pos + size:
                return src, dst, "IPv6/extension"
            protocol, pos = nxt, pos + size
        return src, dst, {6: "TCP", 17: "UDP", 58: "ICMPv6"}.get(protocol, f"IPv6/{protocol}")
    return None


class Aggregator:
    def __init__(self, scope="all", sources=()):
        self.scope, self.sources = scope, set(sources)
        self.flows, self.dirty = {}, set()
        self.lock = threading.Lock()
        self.totals = {"capturedPackets": 0, "packets": 0, "bytes": 0, "ignoredPackets": 0,
                       "unparsedPackets": 0, "overflowPackets": 0, "truncatedPackets": 0}

    def add(self, data, linktype, length, timestamp, captured_length=None):
        decoded = decode_packet(data, linktype)
        with self.lock:
            self.totals["capturedPackets"] += 1
            if (len(data) if captured_length is None else captured_length) < length:
                self.totals["truncatedPackets"] += 1
            if not decoded:
                self.totals["unparsedPackets"] += 1
                return
            src, dst, protocol = decoded
            if self.scope == "outgoing" and src not in self.sources:
                self.totals["ignoredPackets"] += 1
                return
            self.totals["packets"] += 1
            self.totals["bytes"] += length
            if dst not in self.flows and len(self.flows) >= 10000:
                self.totals["overflowPackets"] += 1
                return
            flow = self.flows.setdefault(dst, {"ip": dst, "packets": 0, "bytes": 0, "protocols": {},
                                               "sources": {}, "firstSeen": timestamp, "lastSeen": timestamp})
            flow["packets"] += 1
            flow["bytes"] += length
            flow["protocols"][protocol] = flow["protocols"].get(protocol, 0) + 1
            if src in flow["sources"] or len(flow["sources"]) < 64:
                flow["sources"][src] = flow["sources"].get(src, 0) + 1
            flow["firstSeen"] = min(timestamp, flow["firstSeen"])
            flow["lastSeen"] = max(timestamp, flow["lastSeen"])
            self.dirty.add(dst)

    def flush(self):
        with self.lock:
            flows = [self.flows[ip] for ip in self.dirty]
            emit({"event": "batch", "totals": self.totals, "flows": flows})
            self.dirty.clear()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["interfaces", "live", "offline"])
    parser.add_argument("--interfaces", default="")
    parser.add_argument("--file")
    parser.add_argument("--scope", choices=["all", "outgoing"], default="all")
    parser.add_argument("--sources", default="")
    parser.add_argument("--record-dir")
    parser.add_argument("--seconds", type=float, default=0)
    args = parser.parse_args()
    pcap = Pcap()
    if args.mode == "interfaces":
        emit({"event": "interfaces", "interfaces": pcap.devices()})
        return
    devices = pcap.devices() if args.mode == "live" else []
    selected = [d for d in devices if d["id"] in args.interfaces.split(",")]
    sources = [str(ipaddress.ip_address(ip.strip())) for ip in args.sources.split(",") if ip.strip()]
    if args.mode == "live":
        if not selected:
            raise RuntimeError("请选择可用网卡")
        sources = list({ip for d in selected for ip in d["addresses"] if not ipaddress.ip_address(ip).is_loopback})
        if not sources:
            raise RuntimeError("网卡没有可用的本机 IP 地址")
        args.scope = "outgoing"
    elif args.scope == "outgoing" and not sources:
        raise RuntimeError("出站分析需要指定 PCAP 中的源 IP")
    aggregate, stop = Aggregator(args.scope, sources), threading.Event()
    handles, errors, recordings, recording_limited = [], [], [], []
    if args.mode == "live":
        for index, device in enumerate(selected):
            error = C.create_string_buffer(256)
            handle = pcap.lib.pcap_open_live(device["id"].encode(), 128, 0, 200, error)
            if not handle:
                for old, *_ in handles:
                    pcap.lib.pcap_close(old)
                raise RuntimeError(f"无法打开网卡 {device['name']}：{error.value.decode(errors='replace')}。Npcap 若限制为管理员，请以管理员权限运行服务。")
            if pcap.lib.pcap_setnonblock(handle, 1, error):
                pcap.lib.pcap_close(handle)
                raise RuntimeError("无法设置非阻塞抓包")
            bpf = BPF()
            # Kernel filter: capture only traffic sourced by the selected adapter.
            expression = "(ip or ip6) and (" + " or ".join(f"src host {ip}" for ip in device["addresses"] if not ipaddress.ip_address(ip).is_loopback) + ")"
            if pcap.lib.pcap_compile(handle, C.byref(bpf), expression.encode(), 1, 0xFFFFFFFF) or pcap.lib.pcap_setfilter(handle, C.byref(bpf)):
                pcap.lib.pcap_close(handle)
                raise RuntimeError("无法设置网卡出站过滤器")
            pcap.lib.pcap_freecode(C.byref(bpf))
            dump = None
            if args.record_dir:
                Path(args.record_dir).mkdir(parents=True, exist_ok=True)
                name = f"adapter-{index + 1}.pcap"
                dump = pcap.lib.pcap_dump_open(handle, os.fsencode(str(Path(args.record_dir) / name)))
                if not dump:
                    pcap.lib.pcap_close(handle)
                    raise RuntimeError("无法创建 PCAP 记录")
                recordings.append(name)
            handles.append((handle, pcap.lib.pcap_datalink(handle), dump))
    else:
        error = C.create_string_buffer(256)
        handle = pcap.lib.pcap_open_offline(os.fsencode(args.file), error)
        if not handle:
            raise RuntimeError("PCAP 文件无法读取：" + error.value.decode(errors="replace"))
        handles.append((handle, pcap.lib.pcap_datalink(handle), None))
    emit({"event": "ready", "scope": args.scope, "sourceIPs": sources, "interfaces": selected, "recordings": recordings})

    def commands():
        for line in sys.stdin:
            if line.strip() == "stop":
                stop.set()
                return
        stop.set()

    if args.mode == "live":
        threading.Thread(target=commands, daemon=True).start()

    def read(handle, linktype, dump):
        header, data = C.POINTER(Header)(), C.POINTER(C.c_ubyte)()
        recording_bytes, recording_active = 24, True
        try:
            while not stop.is_set():
                code = pcap.lib.pcap_next_ex(handle, C.byref(header), C.byref(data))
                if code == 0:
                    stop.wait(0.01)
                    continue
                if code == -2:
                    break
                if code < 0:
                    raise RuntimeError(pcap.lib.pcap_geterr(handle).decode(errors="replace"))
                hdr = header.contents
                # Do not construct packet objects or retain payload in memory.
                aggregate.add(C.string_at(data, min(hdr.caplen, 256)), linktype, hdr.length, hdr.sec + hdr.usec / 1e6, hdr.caplen)
                if dump and recording_active and recording_bytes + 16 + hdr.caplen > 256 * 1024 * 1024:
                    recording_active = False
                    recording_limited.append(True)
                if dump and recording_active:
                    pcap.lib.pcap_dump(dump, header, data)
                    recording_bytes += 16 + hdr.caplen
        except Exception as exc:
            errors.append(str(exc))
            stop.set()

    workers = [threading.Thread(target=read, args=entry, daemon=True) for entry in handles]
    for worker in workers:
        worker.start()
    started = time.monotonic()
    while any(worker.is_alive() for worker in workers):
        if args.seconds and time.monotonic() - started >= args.seconds:
            stop.set()
        aggregate.flush()
        time.sleep(0.75)
    drops = []
    for handle, _, dump in handles:
        if args.mode == "live":
            stats = Stats()
            if not pcap.lib.pcap_stats(handle, C.byref(stats)):
                drops.append({"received": stats.received, "dropped": stats.dropped, "interfaceDropped": stats.interfaceDropped})
        if dump:
            pcap.lib.pcap_dump_close(dump)
        pcap.lib.pcap_close(handle)
    aggregate.flush()
    if errors:
        raise RuntimeError("; ".join(errors))
    emit({"event": "done", "durationMs": round((time.monotonic() - started) * 1000), "captureStats": drops, "recordings": recordings, "recordingLimited": bool(recording_limited)})


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        emit({"event": "error", "error": str(error)})
        sys.exit(1)
