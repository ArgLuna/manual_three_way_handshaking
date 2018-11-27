iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP -s 192.168.168.232 -d 192.168.168.69
