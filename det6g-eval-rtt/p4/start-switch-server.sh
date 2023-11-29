#!/bin/bash

P4_FILE_PREFIX="switch-forward"
if [[ "$#" == "1" ]]; then
	P4_FILE_PREFIX=$(basename "$1" .p4)
fi

# namespace name
NS="server"
VETH="veth-$NS"

sudo ip link del "$VETH"
#sudo ip link del veth1 
sudo ip netns del "$NS"
sudo ip netns add "$NS"


# add a dual virtual NICs
sudo ip link add name "$VETH" type veth peer name "veth1"
# disable TCP offload to avoid incorrect checksum
sudo ethtool -K "$VETH" tso off gso off gro off tx off
sudo ethtool -K   veth1 tso off gso off gro off tx off

# change MAC addresses
sudo ip link set dev "$VETH" address 00:00:00:00:00:01
sudo ip link set dev   veth1 address 00:00:00:00:00:02

# config a NIC
#sudo ip address add 10.0.1.10/24 dev "$VETH"
sudo sysctl net.ipv6.conf.$VETH.disable_ipv6=1
sudo ip link set dev "$VETH" up

# move a NIC to the $NS namespace
sudo ip link set veth1 netns "$NS"

sudo ip netns exec "$NS" ip address add 192.168.100.1/24 dev veth1
sudo ip netns exec "$NS" ip link set veth1 up
sudo ip netns exec "$NS" ip route add 0.0.0.0/0 dev veth1
sudo ip netns exec "$NS" arp -s 10.45.0.10 00:00:00:00:00:01

# add NIC to receive INT packets
sudo ip link add int-mon type dummy
sudo ip link set dev int-mon up


function conf_switch(){
	simple_switch_CLI --thrift-port 9091
}

function config_int(){
	echo "Configure INT"
	echo "table_add tb_int_config_transit set_transit => 2" | conf_switch
	#do INT on any packet
	echo "table_add tb_int_config_source set_source 10.0.1.11&&&0x00000000 5001&&&0x0000 10.0.0.11&&&0x00000000 5001&&&0x0000 => 4 10 0xFFFF 0" | conf_switch
	# echo "table_add tb_int_config_sink set_sink 1 => 3" | simple_switch_CLI
	echo "mirroring_add 1 3" | conf_switch
	echo
	echo "P4 switch is ready at server side"
	echo
}

(sleep 3 && config_int )&
DEBUG="--log-level info --pcap=./ --log-console"
DEBUG="--log-level error --log-console"
DEBUG=""
# start BMv2 switch
exec sudo simple_switch -i 1@ogstun -i 2@"$VETH" -i 3@int-mon  --thrift-port 9091 $DEBUG --device-id 1  "$P4_FILE_PREFIX".json

#sleep 5
#echo start server
#sudo ip netns exec server ../client-server/server 5000