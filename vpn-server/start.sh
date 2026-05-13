#!/bin/bash
set -e

# Generate keys if not present
if [ ! -f /etc/wireguard/server_private.key ]; then
  wg genkey | tee /etc/wireguard/server_private.key | wg pubkey > /etc/wireguard/server_public.key
  wg genkey | tee /etc/wireguard/client_private.key | wg pubkey > /etc/wireguard/client_public.key
fi

SERVER_PRIV=$(cat /etc/wireguard/server_private.key)
SERVER_PUB=$(cat /etc/wireguard/server_public.key)
CLIENT_PRIV=$(cat /etc/wireguard/client_private.key)
CLIENT_PUB=$(cat /etc/wireguard/client_public.key)

cat > /etc/wireguard/wg0.conf << EOF
[Interface]
Address = 10.0.0.1/24
PrivateKey = ${SERVER_PRIV}
ListenPort = 51820
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
PublicKey = ${CLIENT_PUB}
AllowedIPs = 10.0.0.2/32
EOF

echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
sysctl -p

wg-quick up wg0

echo "=============================="
echo "SERVER PUBLIC KEY: ${SERVER_PUB}"
echo "CLIENT PRIVATE KEY: ${CLIENT_PRIV}"
echo "CLIENT IP: 10.0.0.2"
echo "=============================="

# Keep running
tail -f /dev/null
