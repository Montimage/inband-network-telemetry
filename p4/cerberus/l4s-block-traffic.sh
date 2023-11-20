#!/bin/bash
# This script will be called as below
# ./l4s-block-traffic.sh ips "10.0.0.1, 1.1.1.1,..."
#
# uncomment the line bellow to verify:
date      >> /tmp/l4s-block-traffic.log
echo "$@" >> /tmp/l4s-block-traffic.log

IPs=$2

# Run any command as you want here, e.g.,
# echo $IPs | ssh root@tata -- python3 block.py

# The output will be shown back to user via Web GUI:
# - stdout will be shown in "blue" banners
# - stderr will be shown in "red" banners
#
# Just an example:
#sleep 1
#echo "Connected to Tofino switch"
#sleep 2
#echo "Updated table configuration"
#sleep 2
#echo "Blocked successfully IPs: $IPs"

echo $IPs
#clear space
#IP=$(echo "${IP//[$'\t\r\n']}")
# syntax: table_add <table-name> <key-1> <key-2> ... => <val-1> <val-2>
echo "table_add tb_blocklist source $IPs => 1" | tee -a /tmp/l4s-block-traffic.log | simple_switch_CLI | tee -a /tmp/l4s-block-traffic.log
