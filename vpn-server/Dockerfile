FROM ubuntu:22.04
RUN apt-get update && apt-get install -y wireguard iproute2 iptables && rm -rf /var/lib/apt/lists/*
COPY start.sh /start.sh
RUN chmod +x /start.sh
CMD ["/start.sh"]
