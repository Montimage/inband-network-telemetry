#!/bin/bash

# start 5G core
sudo ./open5gs/start.sh

# start gNodeB
(cd ueransim && ./start-gnb.sh) &

(cd ueransim && sudo ./start-ue.sh) &