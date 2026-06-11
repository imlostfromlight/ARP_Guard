import base64
import subprocess
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


def _default_iface() -> str:
    try:
        out = subprocess.check_output(['ip', 'route', 'get', '8.8.8.8'], text=True)
        parts = out.split()
        return parts[parts.index('dev') + 1]
    except Exception:
        return 'eth0'


def generate_keypair() -> dict:
    priv = X25519PrivateKey.generate()
    priv_bytes = priv.private_bytes_raw()
    pub_bytes = priv.public_key().public_bytes_raw()
    return {
        'private': base64.b64encode(priv_bytes).decode(),
        'public': base64.b64encode(pub_bytes).decode(),
    }


def generate_full_config(server_ip: str, server_port: int = 51820,
                          client_tunnel_ip: str = '10.0.0.2',
                          dns: str = '1.1.1.1') -> dict:
    server_kp = generate_keypair()
    client_kp = generate_keypair()
    iface = _default_iface()

    server_config = (
        f"[Interface]\n"
        f"PrivateKey = {server_kp['private']}\n"
        f"Address = 10.0.0.1/24\n"
        f"ListenPort = {server_port}\n"
        f"PostUp = sysctl -w net.ipv4.ip_forward=1; "
        f"iptables -A FORWARD -i wg0 -j ACCEPT; "
        f"iptables -t nat -A POSTROUTING -o {iface} -j MASQUERADE\n"
        f"PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; "
        f"iptables -t nat -D POSTROUTING -o {iface} -j MASQUERADE\n\n"
        f"[Peer]\n"
        f"PublicKey = {client_kp['public']}\n"
        f"AllowedIPs = {client_tunnel_ip}/32\n"
    )

    client_config = (
        f"[Interface]\n"
        f"PrivateKey = {client_kp['private']}\n"
        f"Address = {client_tunnel_ip}/32\n"
        f"DNS = {dns}\n\n"
        f"[Peer]\n"
        f"PublicKey = {server_kp['public']}\n"
        f"Endpoint = {server_ip}:{server_port}\n"
        f"AllowedIPs = 0.0.0.0/0\n"
        f"PersistentKeepalive = 25\n"
    )

    return {
        'server_config': server_config,
        'client_config': client_config,
        'server_pubkey': server_kp['public'],
        'client_pubkey': client_kp['public'],
        'client_privkey': client_kp['private'],
    }


def deploy_server_config(server_config: str) -> dict:
    config_path = '/etc/wireguard/wg0.conf'
    try:
        with open(config_path, 'w') as f:
            f.write(server_config)
        subprocess.run(['wg-quick', 'down', 'wg0'], capture_output=True)
        result = subprocess.run(['wg-quick', 'up', 'wg0'], capture_output=True, text=True, check=True)
        return {'success': True, 'output': result.stdout}
    except PermissionError:
        return {'success': False, 'error': 'Permission denied — run backend as root'}
    except FileNotFoundError:
        return {'success': False, 'error': 'wg-quick not found — install WireGuard on this machine'}
    except subprocess.CalledProcessError as e:
        return {'success': False, 'error': e.stderr or 'wg-quick failed'}
    except Exception as e:
        return {'success': False, 'error': str(e)}
