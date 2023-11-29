#!/bin/bash
# This script will be called as below
# ./unblock-traffic.sh ips "10.0.0.1,1.1.1.1,..."
#
# uncomment the line bellow to verify:
date >> /tmp/unblock-traffic.log
echo "$@" >> /tmp/unblock-traffic.log


IPs=$2

function conf_switch(){
	simple_switch_CLI --thrift-port 9092
}


# Run any command as you want here, e.g.,
# echo $IPs | ssh root@tata -- python3 unblock.py

# clear P4 block list
# the output will be shown back to user via Web GUI
echo "table_clear tb_blocklist" | conf_switch | tee -a /tmp/unblock-traffic.log
echo "Unblocked successfully all IPs"

# empty database
mongo mmt-data --eval 'db.security.drop()' >> /tmp/unblock-traffic.log
echo "Cleaned alerts"