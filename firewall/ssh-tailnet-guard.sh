#!/bin/sh
# Privileged deployment reference: block non-Tailscale TCP/22 in both families.
# Never run this on the management workstation. Keep independent recovery access.
set -eu
for tool in /usr/sbin/iptables /usr/sbin/ip6tables; do
    if ! "$tool" -w 5 -C INPUT ! -i tailscale0 -p tcp --dport 22 -m comment --comment pi-management-tailnet-only -j DROP; then
        "$tool" -w 5 -I INPUT 1 ! -i tailscale0 -p tcp --dport 22 -m comment --comment pi-management-tailnet-only -j DROP
    fi
done
