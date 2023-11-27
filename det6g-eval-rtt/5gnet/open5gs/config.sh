#!/bin/bash

#import subscribers
mongoimport --db open5gs --collection subscribers --type=json --drop --file subscribers.json

sudo iptables -I INPUT -i ogstun -j ACCEPT
### Enable IPv4/IPv6 Forwarding
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv6.conf.all.forwarding=1

### Add NAT Rule
sudo iptables -t nat -A POSTROUTING -s 10.45.0.0/16 ! -o ogstun -j MASQUERADE
sudo ip6tables -t nat -A POSTROUTING -s 2001:db8:cafe::/48 ! -o ogstun -j MASQUERADE


# create a NIC for communication between RAN and Core
# namespace name
NS="ran"
VETH="veth-ran-core"

sudo ip link del "$VETH"
#sudo ip link del veth1
sudo ip netns del "$NS"
sudo ip netns add "$NS"

# add a dual virtual NICs
sudo ip link add name "$VETH" type veth peer name "veth1"

# config a NIC
#sudo ip address add 10.0.2.10/24 dev "$VETH"
sudo sysctl net.ipv6.conf.$VETH.disable_ipv6=1
sudo ip address add 192.168.10.1/24 dev "$VETH"
sudo ip link set dev "$VETH" up


# move a NIC to the $NS namespace
sudo ip link set veth1 netns "$NS"
# 10.45.0.10 = ip of UE
sudo ip netns exec "$NS" ip address add 192.168.10.2/24 dev veth1
sudo ip netns exec "$NS" ip link set veth1 up
sudo ip netns exec "$NS" ip route add 0.0.0.0/0 dev veth1

# not sure why nr-gnb needs to listen on 127.0.0.1
# => create a loopback
sudo ip netns exec ran ifconfig lo 127.0.0.1 netmask 255.0.0.0 up

sudo cp amf.yaml upf.yaml /etc/open5gs/
sudo service open5gs-amfd restart
sudo service open5gs-upfd restart