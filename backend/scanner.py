import socket
import ipaddress
from scapy.all import ARP, Ether, srp, conf, get_if_addr, get_if_hwaddr, get_if_list

def _vendor(mac: str) -> str:
    try:
        return conf.manufdb._get_manuf(mac) or ""
    except Exception:
        return ""


def auto_detect_iface() -> str:
    """Pick the interface with a real routable IP, preferring hotspot/WiFi subnets."""
    candidates = []
    for iface in get_if_list():
        try:
            ip = get_if_addr(iface)
            if not ip or ip == "0.0.0.0" or ip.startswith("127.") or ip.startswith("169.254."):
                continue
            candidates.append((iface, ip))
        except Exception:
            continue
    # Prefer common hotspot/private ranges: 192.168.43.x, 10.x, 172.x, 192.168.x
    for iface, ip in candidates:
        if ip.startswith("192.168.43.") or ip.startswith("10."):
            return iface
    for iface, ip in candidates:
        if ip.startswith("172.20."):
            return iface
    for iface, ip in candidates:
        if ip.startswith("192.168."):
            return iface
    if candidates:
        return candidates[0][0]
    return conf.iface


def get_local_info(iface: str) -> dict:
    ip = get_if_addr(iface)
    mac = get_if_hwaddr(iface)
    _, _, gw_ip = conf.route.route("0.0.0.0")
    network = str(ipaddress.ip_network(f"{ip}/24", strict=False))
    return {"ip": ip, "mac": mac, "gateway_ip": gw_ip, "network": network}


def scan_network(iface: str) -> dict:
    """
    ARP-scan the /24 subnet of the given interface.
    Returns local info + list of discovered devices.
    """
    info = get_local_info(iface)
    network = info["network"]
    gw_ip = info["gateway_ip"]

    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network),
        iface=iface,
        timeout=3,
        verbose=False,
    )

    devices = []
    gw_mac = None
    for _, recv in ans:
        ip = recv.psrc
        mac = recv.hwsrc.lower()
        if ip == info["ip"]:          # skip self
            continue
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            hostname = ""
        is_gateway = ip == gw_ip
        if is_gateway:
            gw_mac = mac
        devices.append({
            "ip": ip,
            "mac": mac,
            "hostname": hostname,
            "vendor": _vendor(mac),
            "is_gateway": is_gateway,
        })

    # Sort: gateway first, then by IP
    devices.sort(key=lambda d: (not d["is_gateway"], list(map(int, d["ip"].split(".")))))

    info["gateway_mac"] = gw_mac
    info["devices"] = devices
    return info
