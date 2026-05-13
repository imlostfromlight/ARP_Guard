import base64
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


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

    server_config = (
        f"[Interface]\n"
        f"PrivateKey = {server_kp['private']}\n"
        f"Address = 10.0.0.1/24\n"
        f"ListenPort = {server_port}\n"
        f"PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; "
        f"iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE\n"
        f"PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; "
        f"iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE\n\n"
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
