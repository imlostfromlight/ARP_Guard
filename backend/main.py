import asyncio
import threading
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from event_bus import EventBus
from sniffer import Sniffer
from arp_guard import ArpGuard
from attacker import Attacker
from scanner import scan_network, get_local_info, auto_detect_iface
from dns_spoofer import DnsSpoofer
from phish_server import PhishServer
from vpn import generate_keypair, generate_full_config, deploy_server_config

try:
    from scapy.all import get_if_list, get_if_addr
    from scapy.arch.windows import get_windows_if_list
    def get_interfaces():
        raw = get_windows_if_list()
        result = []
        for i in raw:
            name = i["name"]
            desc = i.get("description") or name
            try:
                ip = get_if_addr(name)
                if ip and ip != "0.0.0.0":
                    label = f"{desc}  [{ip}]"
                else:
                    label = desc
            except Exception:
                label = desc
            result.append({"id": name, "label": label})
        return result
except Exception:
    from scapy.all import get_if_list
    def get_interfaces():
        return [{"id": n, "label": n} for n in get_if_list()]

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------

bus = EventBus()
guard = ArpGuard(bus)
sniffer = Sniffer(bus)
attacker = Attacker(bus)
dns_spoofer = DnsSpoofer(bus)
phish = PhishServer(bus)
bus.set_arp_guard(guard)

# ---------------------------------------------------------------------------
# Startup / shutdown
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    bus.set_loop(asyncio.get_event_loop())
    # Periodic bitrate broadcaster
    asyncio.create_task(_bitrate_task())
    yield
    sniffer.stop()
    guard.set_protect(False)
    attacker.stop()
    dns_spoofer.stop()
    phish.stop()

async def _bitrate_task():
    while True:
        await asyncio.sleep(1)
        bus.emit_bitrate(sniffer.get_bitrate())

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# REST endpoints
# ---------------------------------------------------------------------------

@app.get("/api/interfaces")
def list_interfaces():
    return {"interfaces": get_interfaces()}


class StartRequest(BaseModel):
    iface: str

@app.post("/api/start")
def start_sniffing(req: StartRequest):
    guard.set_iface(req.iface)
    sniffer.start(req.iface)
    return {"status": "started", "iface": req.iface}

@app.post("/api/stop")
def stop_sniffing():
    sniffer.stop()
    return {"status": "stopped"}


class GoldenEntry(BaseModel):
    ip: str
    mac: str

@app.get("/api/golden-table")
def get_golden_table():
    return {"table": guard.golden_table}

@app.post("/api/golden-table")
def add_golden_entry(entry: GoldenEntry):
    guard.add_golden(entry.ip, entry.mac)
    return {"status": "added", "ip": entry.ip, "mac": entry.mac}

@app.delete("/api/golden-table/{ip}")
def delete_golden_entry(ip: str):
    guard.remove_golden(ip)
    return {"status": "deleted", "ip": ip}


class ProtectRequest(BaseModel):
    enabled: bool

@app.post("/api/protect")
def set_protect(req: ProtectRequest):
    guard.set_protect(req.enabled)
    return {"protect": req.enabled}

# ---------------------------------------------------------------------------
# Network scan
# ---------------------------------------------------------------------------

@app.get("/api/scan")
def scan(iface: str = None):
    target = iface or auto_detect_iface()
    result = scan_network(target)
    # auto-start sniffing on the detected iface
    if not sniffer._thread or not sniffer._thread.is_alive():
        guard.set_iface(target)
        sniffer.start(target)
    return result

@app.get("/api/network-info")
def network_info(iface: str = None):
    return get_local_info(iface or auto_detect_iface())


# ---------------------------------------------------------------------------
# Attacker (demo — ARP poisoning)
# ---------------------------------------------------------------------------

class AttackRequest(BaseModel):
    target_ip: str
    target_mac: str
    gateway_ip: str
    gateway_mac: str

@app.post("/api/attack/start")
def start_attack(req: AttackRequest):
    if not sniffer.iface:
        return {"error": "Start sniffing first"}
    attacker.start(
        sniffer.iface,
        req.target_ip, req.target_mac,
        req.gateway_ip, req.gateway_mac,
    )
    return {"status": "attacking", "target": req.target_ip}

@app.post("/api/attack/stop")
def stop_attack():
    attacker.stop()
    return {"status": "stopped"}

@app.get("/api/attack/status")
def attack_status():
    return {
        "active": attacker.active,
        "target_ip": attacker.target_ip,
        "target_mac": attacker.target_mac,
    }


# ---------------------------------------------------------------------------
# DNS Spoofer
# ---------------------------------------------------------------------------

class DnsSpoofRequest(BaseModel):
    target_ip: str
    redirect_ip: str

@app.post("/api/dns/start")
def start_dns(req: DnsSpoofRequest):
    if not sniffer.iface:
        return {"error": "Start sniffing first"}
    dns_spoofer.start(sniffer.iface, req.target_ip, req.redirect_ip)
    return {"status": "started"}

@app.post("/api/dns/stop")
def stop_dns():
    dns_spoofer.stop()
    return {"status": "stopped"}

@app.get("/api/dns/status")
def dns_status():
    return {"active": dns_spoofer.active, "target_ip": dns_spoofer.target_ip}

# ---------------------------------------------------------------------------
# VPN key generation
# ---------------------------------------------------------------------------

@app.post("/api/vpn/keygen")
def vpn_keygen():
    client = generate_keypair()
    return {'client_privkey': client['private'], 'client_pubkey': client['public']}


class VpnGenerateRequest(BaseModel):
    server_ip: str
    server_port: int = 51820
    client_tunnel_ip: str = '10.0.0.2'
    dns: str = '1.1.1.1'

@app.post("/api/vpn/generate")
def vpn_generate(req: VpnGenerateRequest):
    return generate_full_config(req.server_ip, req.server_port, req.client_tunnel_ip, req.dns)


class VpnDeployRequest(BaseModel):
    server_config: str

@app.post("/api/vpn/deploy")
def vpn_deploy(req: VpnDeployRequest):
    return deploy_server_config(req.server_config)

# ---------------------------------------------------------------------------
# Phish server
# ---------------------------------------------------------------------------

class PhishRequest(BaseModel):
    port: int = 80

@app.post("/api/phish/start")
def start_phish(req: PhishRequest):
    phish.start(req.port)
    return {"status": "started", "port": req.port}

@app.post("/api/phish/stop")
def stop_phish():
    phish.stop()
    return {"status": "stopped"}

@app.get("/api/phish/status")
def phish_status():
    return {"active": phish.active, "port": phish.port}

# ---------------------------------------------------------------------------

@app.get("/api/status")
def status():
    return {
        "sniffing": sniffer._thread is not None and sniffer._thread.is_alive(),
        "iface": sniffer.iface,
        "protect": guard.protect,
        "golden_table": guard.golden_table,
    }

# ---------------------------------------------------------------------------
# WebSocket
# ---------------------------------------------------------------------------

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    bus.register(ws)
    try:
        while True:
            await ws.receive_text()  # keep alive; client may send pings
    except WebSocketDisconnect:
        pass
    finally:
        bus.unregister(ws)
