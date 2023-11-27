#!/bin/bash
sudo ip netns exec ran ./software/build/nr-ue -c ./conf/open5gs-ue.yaml
