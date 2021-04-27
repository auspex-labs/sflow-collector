#!/usr/bin/python
from socket import socket, AF_INET, SOCK_DGRAM
import sflow

# Basic Listener

recordClasses = {
    (1, 0, 1): sflow.sFlowRawPacketHeader,
    (1, 0, 2): sflow.sFlowEthernetFrame,
    (1, 0, 3): sflow.sFlowSampledIpv4,
    (1, 0, 4): sflow.sFlowSampledIpv6,
    (1, 0, 1001): sflow.sFlowExtendedSwitch,
    (1, 0, 1002): sflow.sFlowExtendedRouter,
    (1, 0, 1003): sflow.sFlowExtendedGateway,
    (1, 0, 1004): sflow.sFlowExtendedUser,
    (1, 0, 1005): sflow.sFlowExtendedUrl,
    (1, 0, 1006): sflow.sFlowExtendedMpls,
    (1, 0, 1007): sflow.sFlowExtendedNat,
    (1, 0, 1008): sflow.sFlowExtendedMplsTunnel,
    (1, 0, 1009): sflow.sFlowExtendedMplsVc,
    (1, 0, 1010): sflow.sFlowExtendedMpls_FTN,
    (1, 0, 1011): sflow.sFlowExtendedMpls_LDP_FEC,
    (1, 0, 1012): sflow.sFlowExtendedVlantunnel,
    (1, 0, 2100): sflow.sFlowExtendedSocketIpv4,
    (1, 0, 2101): sflow.sFlowExtendedSocketIpv6,
    (2, 0, 1): sflow.sFlowIfCounters,
    (2, 0, 2): sflow.sFlowEthernetInterface,
    (2, 0, 3): sflow.sFlowTokenringCounters,
    (2, 0, 4): sflow.sFlowVgCounters,
    (2, 0, 5): sflow.sFlowVLAN,
    (2, 0, 1001): sflow.sFlowProcessor,
    (2, 0, 1004): sflow.sFlowOfPort,
    (2, 0, 1005): sflow.sFlowPortName,
    (2, 0, 2000): sflow.sFlowHostDescr,
    (2, 0, 2001): sflow.sFlowHostAdapters,
    (2, 0, 2002): sflow.sFlowHostParent,
    (2, 0, 2003): sflow.sFlowHostCPU,
    (2, 0, 2004): sflow.sFlowHostMemory,
    (2, 0, 2005): sflow.sFlowHostDiskIO,
    (2, 0, 2006): sflow.sFlowHostNetIO,
    (2, 0, 2007): sflow.sFlowMib2IP,
    (2, 0, 2008): sflow.sFlowMib2ICMP,
    (2, 0, 2009): sflow.sFlowMib2TCP,
    (2, 0, 2010): sflow.sFlowMib2UDP,
    (2, 0, 2100): sflow.sFlowVirtNode,
    (2, 0, 2101): sflow.sFlowVirtCPU,
    (2, 0, 2102): sflow.sFlowVirtMemory,
    (2, 0, 2103): sflow.sFlowVirtDiskIO,
    (2, 0, 2104): sflow.sFlowVirtNetIO,
}


UDP_IP = "0.0.0.0"
UDP_PORT = 6343

sock = socket(AF_INET, SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))
print("Collector started")
while True:
    print("Waiting for data")
    # 1386 bytes is the largest possible sFlow packet, by spec 3000 seems to be the number by practice
    data, addr = sock.recvfrom(3000)
    print("Data received")
    sFlowData = sflow.sFlow(data)

    sFlowItems = []
    sFlowItems.append(f'"DG Version": "{sFlowData.dgVersion}"')
    sFlowItems.append(f'"Agent Address": "{sFlowData.agentAddress}"')
    sFlowItems.append(f'"Sub Agent": "{sFlowData.subAgent}"')
    sFlowItems.append(f'"Sequence Number": "{sFlowData.sequenceNumber}"')
    sFlowItems.append(f'"System UpTime": "{sFlowData.sysUpTime}"')
    sFlowPart = f'"sflow": {{{", ".join(sFlowItems)}}}'

    for sample in sFlowData.samples:
        sampleItems = []
        sampleItems.append(f'"Sequence": "{sample.sequence}"')
        sampleItems.append(f'"Enterprise": "{sample.enterprise}"')
        sampleItems.append(f'"Type": "{sample.sampleType}"')
        sampleItems.append(f'"Index": "{sample.sourceIndex}"')
        sampleItems.append(f'"Rate": "{sample.sampleRate}"')
        sampleItems.append(f'"Pool": "{sample.samplePool}"')
        sampleItems.append(f'"Dropped": "{sample.droppedPackets}"')
        sampleItems.append(f'"Input": "{sample.inputIfFormat}"')
        sampleItems.append(f'"Input": "{sample.inputIfValue}"')
        sampleItems.append(f'"Output": "{sample.outputIfFormat}"')
        sampleItems.append(f'"Output": "{sample.outputIfValue}"')
        samplePart = f'"sample": {{{", ".join(sampleItems)}}}'

        for record in sample.records:
            sFlowClass = recordClasses[record.sampleType, record.enterprise, record.format]
            recordClass = sFlowClass(record.len, record.data)
            recordItems = []
            for fieldName, fieldValue in recordClass.__dict__.items():
                if fieldName not in ["len", "data"]:
                    if isinstance(fieldValue, bytes):
                        recordItems.append(f'"{fieldName}": "{list(fieldValue)}"')
                    else:
                        recordItems.append(f"{fieldName}: {fieldValue}")
            recordPart = f'"record": {{{", ".join(recordItems)}}}'
            wholeRecord = f"{{{sFlowPart}, {samplePart}, {recordPart}}}"
            print(wholeRecord)
