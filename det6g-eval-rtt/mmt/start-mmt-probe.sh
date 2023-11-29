#!/bin/bash

sudo docker run --rm -it --network host ghcr.io/montimage/mmt-probe:v1.5.12 -i veth-ran-core -Xsecurity.enable=false -Xredis-output.enable=true -Xsession-report.output-channel=redis
