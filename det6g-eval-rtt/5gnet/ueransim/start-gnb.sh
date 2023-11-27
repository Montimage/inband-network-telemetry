#!/bin/bash
sudo ip netns exec ran ./software/build/nr-gnb -c ./conf/open5gs-gnb.yaml
