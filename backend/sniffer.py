import threading
import time
from collections import deque, defaultdict
from scapy.all import sniff, ARP, IP, TCP, Raw

# Keywords that likely indicate credentials in form data
CRED_KEYS = {"pass", "password", "passwd", "pwd", "secret", "token",
             "user", "username", "login", "email", "auth", "key"}

def _highlight_form(body: str) -> list:
    """Parse url-encoded form body into [{key, value, is_cred}] list."""
    fields = []
    for pair in body.split("&"):
        if "=" in pair:
            k, _, v = pair.partition("=")
            is_cred = any(c in k.lower() for c in CRED_KEYS)
            fields.append({"key": k, "value": v, "is_cred": is_cred})
        else:
            fields.append({"key": pair, "value": "", "is_cred": False})
    return fields


def _parse_http(data: bytes):
    """
    Try to parse a complete HTTP request or response from raw bytes.
    Returns dict or None if incomplete.
    """
    try:
        header_end = data.find(b"\r\n\r\n")
        if header_end == -1:
            return None
        header_bytes = data[:header_end]
        body_bytes = data[header_end + 4:]

        lines = header_bytes.decode("utf-8", errors="replace").split("\r\n")
        first_line = lines[0]
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()

        content_length = int(headers.get("content-length", 0))
        if len(body_bytes) < content_length:
            return None  # incomplete — wait for more data

        body = body_bytes[:content_length].decode("utf-8", errors="replace")

        # Determine direction
        parts = first_line.split(" ")
        if len(parts) >= 2 and parts[0] in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"):
            method, path = parts[0], parts[1]
            form_fields = None
            ct = headers.get("content-type", "")
            if "x-www-form-urlencoded" in ct and body:
                form_fields = _highlight_form(body)
            return {
                "direction": "request",
                "method": method,
                "path": path,
                "headers": headers,
                "body": body,
                "form_fields": form_fields,
            }
        elif first_line.startswith("HTTP/"):
            status = first_line
            return {
                "direction": "response",
                "status": status,
                "headers": headers,
                "body": body[:500],  # truncate binary responses
                "form_fields": None,
            }
    except Exception:
        pass
    return None


class Sniffer:
    def __init__(self, event_bus):
        self.event_bus = event_bus
        self.iface = None
        self._thread = None
        self._stop_flag = threading.Event()

        # Bitrate tracking
        self._byte_window = deque()
        self._lock = threading.Lock()

        # TCP stream reassembly buffers: key = (src_ip, src_port, dst_ip, dst_port)
        self._streams = defaultdict(bytes)
        self._stream_lock = threading.Lock()

    def start(self, iface: str):
        if self._thread and self._thread.is_alive():
            return
        self.iface = iface
        self._stop_flag.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_flag.set()

    def get_bitrate(self) -> float:
        now = time.time()
        with self._lock:
            while self._byte_window and self._byte_window[0][0] < now - 2:
                self._byte_window.popleft()
            total = sum(b for _, b in self._byte_window)
        return total / 2.0

    def _run(self):
        sniff(
            iface=self.iface,
            prn=self._handle_packet,
            store=False,
            stop_filter=lambda _: self._stop_flag.is_set(),
        )

    def _handle_packet(self, pkt):
        # Bitrate
        with self._lock:
            self._byte_window.append((time.time(), len(pkt)))

        # ARP
        if pkt.haslayer(ARP):
            self.event_bus.on_arp(pkt[ARP])

        # HTTP (TCP port 80)
        if pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw):
            tcp = pkt[TCP]
            if tcp.dport != 80 and tcp.sport != 80:
                return
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            key = (src_ip, tcp.sport, dst_ip, tcp.dport)

            with self._stream_lock:
                self._streams[key] += pkt[Raw].load
                buf = self._streams[key]

            parsed = _parse_http(buf)
            if parsed:
                with self._stream_lock:
                    self._streams[key] = b""
                self.event_bus.on_http(parsed, src_ip, dst_ip)
