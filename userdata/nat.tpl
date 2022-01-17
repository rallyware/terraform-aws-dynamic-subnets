#!/bin/bash -xe
exec > >(tee /var/log/user-data.log|logger -t user-data -s 2>/dev/console) 2>&1

sudo yum install iptables-services -y
sudo /sbin/iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv4.ip_local_port_range="1024 65000"
sudo sysctl -w net.ipv4.tcp_tw_reuse=1
sudo sysctl -w net.ipv4.tcp_fin_timeout=15
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=65535
sudo sysctl -w net.ipv4.tcp_max_tw_buckets=400000
sudo sysctl -w net.ipv4.tcp_no_metrics_save=1
sudo sysctl -w net.ipv4.tcp_syn_retries=3
sudo sysctl -w net.ipv4.tcp_synack_retries=3
sudo sysctl -w net.ipv4.tcp_rmem="4096 87380 16777216"
sudo sysctl -w net.ipv4.tcp_wmem="4096 65536 16777216"
sudo sysctl -w net.ipv4.tcp_keepalive_time=200
sudo sysctl -w net.ipv4.tcp_keepalive_intvl=60
sudo sysctl -w net.core.somaxconn=65535
sudo sysctl -w net.core.netdev_max_backlog=16384
sudo sysctl -w net.core.rmem_max=16777216
sudo sysctl -w net.core.wmem_max=16777216
sudo sysctl -w net.ipv4.udp_rmem_min=4096
sudo sysctl -w net.ipv4.udp_wmem_min=4096
sudo sysctl -w net.core.rmem_max=16777216
sudo sysctl -w net.core.wmem_max=16777216

sudo service iptables save
sudo systemctl enable iptables
sudo systemctl start iptables
