import asyncio
import json
from typing import Set
from fastapi import WebSocket

class EventBus:
    """
    Thread-safe bridge between Scapy (sync threads) and FastAPI (async).
    Broadcasts JSON events to all connected WebSocket clients.
    """

    def __init__(self):
        self._clients: Set[WebSocket] = set()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._arp_guard = None  # set after construction

    def set_loop(self, loop: asyncio.AbstractEventLoop):
        self._loop = loop

    def set_arp_guard(self, guard):
        self._arp_guard = guard

    def register(self, ws: WebSocket):
        self._clients.add(ws)

    def unregister(self, ws: WebSocket):
        self._clients.discard(ws)

    # ------------------------------------------------------------------
    # Called from sync Scapy threads — schedule on the asyncio loop
    # ------------------------------------------------------------------

    def on_arp(self, arp_pkt):
        if self._arp_guard:
            self._arp_guard.on_arp(arp_pkt)

    def on_arp_alert(self, ip: str, fake_mac: str, real_mac: str):
        self._emit({
            "type": "arp_alert",
            "ip": ip,
            "fake_mac": fake_mac,
            "real_mac": real_mac,
        })

    def on_arp_clear(self, ip: str):
        self._emit({"type": "arp_clear", "ip": ip})

    def on_attack_started(self, target_ip: str, target_mac: str):
        self._emit({"type": "attack_started", "target_ip": target_ip, "target_mac": target_mac})

    def on_attack_stopped(self, target_ip: str):
        self._emit({"type": "attack_stopped", "target_ip": target_ip})

    def on_http(self, parsed: dict, src: str, dst: str):
        self._emit({
            "type": "http_capture",
            "src": src,
            "dst": dst,
            **parsed,
        })

    def on_dns_spoof(self, domain: str, redirected_to: str):
        self._emit({"type": "dns_spoof", "domain": domain, "redirected_to": redirected_to})

    def on_phish_capture(self, creds: dict, src_ip: str):
        self._emit({"type": "phish_capture", "creds": creds, "src_ip": src_ip})

    def emit_bitrate(self, bps: float):
        self._emit({"type": "bitrate", "bps": bps})

    # ------------------------------------------------------------------

    def _emit(self, data: dict):
        if not self._loop:
            return
        asyncio.run_coroutine_threadsafe(self._broadcast(data), self._loop)

    async def _broadcast(self, data: dict):
        dead = set()
        msg = json.dumps(data)
        for ws in list(self._clients):
            try:
                await ws.send_text(msg)
            except Exception:
                dead.add(ws)
        self._clients -= dead
