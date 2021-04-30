# sflow-collector

sFlow is layer 2 packet summerization protocol intended for developing metrics for system behavior and performance. sFlow transmitters are common on Network Appliances and can be run as services on Linux and Windows hosts.

## Overview

The sflow-collector provides a simple sample collector and a class which will parse the sFlow data and return it to the collector for presentation. 

The code has been refactored from Python 2.7 to Python 3.6+

This is a work in progess.

## Structures

### Completed

opaque | enterprise | format | struct
--- | --- | --- | ---
flowData | 0 | 1 | sampled_header
flowData | 0 | 2 | sampled_ethernet
flowData | 0 | 3 | sampled_ipv4
flowData | 0 | 4 | sampled_ipv6
flowData | 0 | 1001 | extended_switch
flowData | 0 | 1002 | extended_router
flowData | 0 | 1003 | extended_gateway
flowData | 0 | 1004 | extended_user
flowData | 0 | 1005 | extended_url
flowData | 0 | 1006 | extended_mpls
flowData | 0 | 1007 | extended_nat
flowData | 0 | 1008 | extended_mplsTunnel
flowData | 0 | 1009 | extended_mplsVc
flowData | 0 | 1010 | extended_mpls_FTN
flowData | 0 | 1011 | extended_mpls_LDP_FEC
flowData | 0 | 1012 | extended_vlantunnel
flowData | 0 | 2100 | extended_socket_ipv4
flowData | 0 | 2101 | extended_socket_ipv6
counterData | 0 | 1 | if_counters
counterData | 0 | 2 | ethernet_counters
counterData | 0 | 3 | tokenring_counters
counterData | 0 | 4 | vg_counters
counterData | 0 | 5 | vlan_counters
counterData | 0 | 1001 | processor
counterData | 0 | 1004 | of_port
counterData | 0 | 1005 | port_name
counterData | 0 | 2000 | host_descr
counterData | 0 | 2001 | host_adapters
counterData | 0 | 2002 | host_parent
counterData | 0 | 2003 | host_cpu
counterData | 0 | 2004 | host_memory
counterData | 0 | 2005 | host_disk_io
counterData | 0 | 2006 | host_net_io
counterData | 0 | 2007 | mib2_ip_group
counterData | 0 | 2008 | mib2_icmp_group
counterData | 0 | 2009 | mib2_tcp_group
counterData | 0 | 2010 | mib2_udp_group
counterData | 0 | 2100 | virt_node
counterData | 0 | 2101 | virt_cpu
counterData | 0 | 2102 | virt_memory
counterData | 0 | 2103 | virt_disk_io
counterData | 0 | 2104 | virt_net_io

## References

#### sFlow Overview

https://en.wikipedia.org/wiki/SFlow

http://www.sflow.org/developers/specifications.php

http://www.sflow.org/developers/structures.php

#### Structure Diagrams

http://www.sflow.org/developers/diagrams/sFlowV5FlowData.pdf

http://www.sflow.org/developers/diagrams/sFlowV5CounterData.pdf

#### MIB-2 Structures (Counter_Data 0 2007-2010)

http://www.sflow.org/sflow_host_ip.txt

https://www.ietf.org/rfc/rfc1213.txt


