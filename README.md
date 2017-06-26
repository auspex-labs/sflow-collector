# sflow-collector

sFlow is layer 2 packet summerization protocol intended for developing matrics on network behavior and performance. sFlow transmitters can be found on network devices and can be run as services on Window sand Linux. 

## Overview

The sflow-collector provides a simple sample collector and a class which will parse the sFlow data and return it to the collector for presentation. 

This is a work in progess.

## Structures

### Completed

```
opaque		enterprise		format	struct

flow_data		0		2		sampled_ethernet
flow_data		0		1001		extended_switch	

counter_data		0		1		if_counters
counter_data		0		2		ethernet_counters
counter_data		0		2		VLAN_counters
counter_data		0		1001		Processor
counter_data		0		2000		host_description
counter_data		0		2001		host_adapaters
counter_data		0		2003		host_cpu
counter_data		0		2004		host_memory
counter_data		0		2005		host_disk_io
counter_data		0		2006		host_net_io
counter_data		0		2007		mib2_ip_group
counter_data		0		2008		mib2_icmp_group
counter_data		0		2009		mib2_tcp_group
counter_data		0		2010		mib2_udp_group

```

### Planned

```
opaque		enterprise		format	struct

flow_data		0		1		sampled_header
flow_data		8800		2		PMACCT

counter_data		0		2002		host_parent
counter_data		0		2100		virt_node
counter_data		0		2101		virt_cpu
counter_data		0		2102		virt_memory
counter_data		0		2103		virt_disk_io
counter_data		0		2104		virt_net_io
	
```

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


