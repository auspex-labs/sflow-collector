# sflow-collector

sFlow is layer 2 packet summerization protocol intended for developing matrics on network behavior and performance. sFlow transmitters can be found on network devices and can be run as services on Window sand Linux. 

## Overview

The sflow-collector provides a simple sample collector and a class which will parse the sFlow data and return it to the collector for presentation. 

This is a work in progess.

## Structures

### Completed

```
opaque		enterprise		format	struct

counter_data		0		1		if_counters
counter_data		0		2000		host_description
counter_data		0		2003		host_cpu
```

### Planned

```
opaque		enterprise		format	struct

flow_data			0		1		sampled_header
flow_data			0		2		sampled_ethernet
flow_data			0		1001		extended_switch	

counter_data		0		2		ethernet_counters
counter_data		0		2001		host_adapaters
counter_data		0		2004		host_memory
counter_data		0		2005		host_disk_io
counter_data		0		2007		mib2_ip_group
counter_data		0		2008		mib2_icmp_group
counter_data		0		2009		mib2_tcp_group
counter_data		0		2010		mib2_udp_group
```

## References

https://en.wikipedia.org/wiki/SFlow

http://www.sflow.org/developers/specifications.php

http://www.sflow.org/developers/diagrams/sFlowV5FlowData.pdf


