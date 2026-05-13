import threading
import time
from scapy.all import ARP, Ether, sendp, get_if_hwaddr

CORRECTION_RATE = 10  # packets per second

class ArpGuard:
    """
    Maintains a golden table (trusted IP → MAC mappings).
    Detects conflicts and, when protect mode is on, floods corrective ARPs.
    """

    def __init__(self, event_bus):
        self.event_bus = event_bus
        self.golden_table: dict[str, str] = {}   # ip -> mac
        self.protect = False
        self.iface = None

        self._conflict_ips: set[str] = set()
        self._protect_thread: threading.Thread | None = None
        self._stop_protect = threading.Event()
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def set_iface(self, iface: str):
        self.iface = iface

    def add_golden(self, ip: str, mac: str):
        with self._lock:
            self.golden_table[ip] = mac.lower()

    def remove_golden(self, ip: str):
        with self._lock:
            self.golden_table.pop(ip, None)

    def set_protect(self, enabled: bool):
        self.protect = enabled
        if enabled:
            self._start_protection()
        else:
            self._stop_protection()

    def on_arp(self, arp_pkt):
        """Called by the sniffer for every ARP packet."""
        op = arp_pkt.op          # 1=who-has, 2=is-at
        src_ip = arp_pkt.psrc
        src_mac = arp_pkt.hwsrc.lower()

        with self._lock:
            trusted_mac = self.golden_table.get(src_ip)

        if trusted_mac and src_mac != trusted_mac:
            with self._lock:
                self._conflict_ips.add(src_ip)
            self.event_bus.on_arp_alert(src_ip, src_mac, trusted_mac)
        else:
            with self._lock:
                self._conflict_ips.discard(src_ip)
            self.event_bus.on_arp_clear(src_ip)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _start_protection(self):
        if self._protect_thread and self._protect_thread.is_alive():
            return
        self._stop_protect.clear()
        self._protect_thread = threading.Thread(
            target=self._protect_loop, daemon=True
        )
        self._protect_thread.start()

    def _stop_protection(self):
        self._stop_protect.set()

    def _protect_loop(self):
        while not self._stop_protect.is_set():
            with self._lock:
                entries = list(self.golden_table.items())
                iface = self.iface

            if iface:
                for ip, mac in entries:
                    # Broadcast corrective ARP: "ip is at mac"
                    pkt = (
                        Ether(dst="ff:ff:ff:ff:ff:ff")
                        / ARP(op=2, pdst="255.255.255.255", psrc=ip, hwsrc=mac)
                    )
                    try:
                        sendp(pkt, iface=iface, verbose=False)
                    except Exception:
                        pass

            time.sleep(1.0 / CORRECTION_RATE)
