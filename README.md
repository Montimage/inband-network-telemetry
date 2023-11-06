# Introduction

- This repository contains an implementaion a monitoring system by using [In-band Network Telemetry](https://p4.org/p4-spec/docs/INT_v2_1.pdf) and [P4](https://p4.org) language.
- The P4 programs run on [BMv2](https://github.com/p4lang/behavioral-model) virtual switches.
- It has been experimented over a 5G network simulator (ongoing: over 5G air interface)

<img src=img/monitoring-5g.png width=600px>

- It has been used to monitor [L4S](https://datatracker.ietf.org/doc/draft-ietf-tsvwg-l4s-arch) P4-based [switches](https://ieeexplore.ieee.org/document/9631539).
   - for further information: [testbed](https://github.com/mosaico-anr/p4-int-l4s/tree/main/testbed)

<img src=img/monitoring-l4s.jpg width=600px>

# Execution

The implemenation of INT is inside [`int.p4`](p4/int.p4). It is used in [`switch-int.p4`](p4/switch-int.p4) which is a simple forwarding switch within INT, or [`switch-l4s.p4`](p4/switch-l4s.p4) which is an implementation of L4S using P4 within INT integration. Futher test results of the latter is available [here](https://github.com/mosaico-anr/p4-int-l4s)

The P4 switches above are executed by BMv2 virtual switches. Go [here](https://github.com/p4lang/behavioral-model) for further information of compiling and executing a P4 program. For instance:

To compile `switch-int.p4`, run:

```bash
p4c --target bmv2 --arch v1model switch-int.p4
```

The output is `switch-int.json` file which can now be used by BMv2 switch. For example, run the command below to create a switch which bounds its ports 1, 2 to the NICs `eth0`, `eth1` respectively, and it sends INT reports to the collector via `eth3`:

```bash
sudo simple_switch -i 1@eth0 -i 2@eth1 -i 3@eth3 switch-int.json
```


# Configuration

- Enable INT:
```bash
cat "table_add tb_int_config_transit set_transit => 1" | simple_switch_CLI
```

- Configure source node to perform INT only on the packets which have `ip-src`, `port-src`, `ip-dst`, `port-dst`:
``bash
cat "table_add tb_int_config_source set_source ip-src port-src ip-dst port-dst => max-hop hop-metadata-length instruction-mask
```

in which:
   + `max-hop`:  how many INT nodes can add their INT node metadata
   + `hop-metadata-len`: how INT metadata words are added by a single INT node
   + `instruction-mask`: which information (metric to be collected at each hop) must added to the packet

For example:
```bash
cat "table_add tb_int_config_source set_source 10.0.1.11&&&0xFFFFFF00 5001&&&0x0000 10.0.0.11&&&0xFFFFFFFF 5001&&&0x0000 => 4 10 0xFFFF" | simple_switch_CLI
```
to collect all available metric from `10.0.1.x:5001` to `10.0.0.11:5001`. The IPs and ports are given together with their mask to present a rang of IPs or port numbers.

- Configure sink node using this syntax: `mirroring_add <mirror-id> <egress-port>`:

```bash
# cat "table_add tb_int_config_sink set_sink 1 => 3" | simple_switch_CLI
cat "mirroring_add 1 3" | simple_switch_CLI
```


# License

- This repository is copyrighted by Montimage. It is released under [MIT license](./LICENSE).

