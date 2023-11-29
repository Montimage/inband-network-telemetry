#!/bin/bash

sudo docker run --rm -it --network host ghcr.io/montimage/mmt-operator:v1.7.6 -Xinput_mode=redis -Xredis_input.channel=report
