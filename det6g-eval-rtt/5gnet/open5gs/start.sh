#!/bin/bash

echo "Usage: $0 status|stop|start|restart"

ACTION="start"
if [[ "$#" -eq "1" ]]; then
   ACTION="$1" 
fi

#https://open5gs.org/open5gs/docs/guide/01-quickstart/
sudo systemctl "$ACTION" open5gs-mmed
sudo systemctl "$ACTION" open5gs-sgwcd
sudo systemctl "$ACTION" open5gs-smfd
sudo systemctl "$ACTION" open5gs-amfd
sudo systemctl "$ACTION" open5gs-sgwud
sudo systemctl "$ACTION" open5gs-upfd
sudo systemctl "$ACTION" open5gs-hssd
sudo systemctl "$ACTION" open5gs-pcrfd
sudo systemctl "$ACTION" open5gs-nrfd
sudo systemctl "$ACTION" open5gs-ausfd
sudo systemctl "$ACTION" open5gs-udmd
sudo systemctl "$ACTION" open5gs-pcfd
sudo systemctl "$ACTION" open5gs-nssfd
sudo systemctl "$ACTION" open5gs-bsfd
sudo systemctl "$ACTION" open5gs-udrd
