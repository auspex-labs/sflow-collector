import socket

import sflow

# Basic Listener

UDP_IP = "0.0.0.0"
UDP_PORT = 6343

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

"""

counter_1_test = b'\x00\x00\x00\x01\x00\x00\x00\x01\xc0\xa8\x00\x07\x00\x00\x00\x00\x00\x04\x97\x03\xb4\xf3\x00\x00\x00\x05\x00\x00\x00\x02\x00\x00\x00\xa8\x00\x02A)\x00\x00\x00\x08\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00X\x00\x00\x00\x08\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00\x00\x00\nI\xd1\x00\x00\x18\xa5\x00\x00\x00\x00\x00\x00\x00\x13\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x8e\xaeI\x00\x00(\xd3\x00\x00\x05\x9f\x00\x00\x01Z\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x004\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\xa8\x00\x02A)\x00\x00\x00\t\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00X\x00\x00\x00\t\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x004\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\xa8\x00\x02A)\x00\x00\x00\n\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00X\x00\x00\x00\n\x00\x00\x00\x06\x00\x00\x00\x00;\x9a\xca\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\x00\x00\x002\xa6e\xf2\x00V\x1f\\\x00\x00\xf4B\x00\x02\x11\xcd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xcc\xa7\x05B\x00w\r\xd1\x00\x1f}\xf8\x00\x14\xa0*\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x004\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\xa8\x00\x02A)\x00\x00\x00\x0b\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00X\x00\x00\x00\x0b\x00\x00\x00\x06\x00\x00\x00\x00\x05\xf5\xe1\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\x00\x00\x00\x00\x15 \xac\x00\x00%\xd0\x00\x00.\x97\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00,\x94\x86\xf3\x00\x00R\x10\x00C\xa1\x00\x16\xb2\x0f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x004\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\xa8\x00\x02A)\x00\x00\x00\x0c\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00X\x00\x00\x00\x0c\x00\x00\x00\x06\x00\x00\x00\x00;\x9a\xca\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\x00\x00\x02\xd0AA\x1a\x00\xbc7\xfa\x00\x1c\xc6\xab\x00\x10\x02\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00eH$b\x00\x8d\xe9\xdd\x00\x03\xaa\xb0\x00\x06\xaar\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x004\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
record = sflow.sFlowIfCounter(len(counter_1_test),counter_1_test)
print("If Counter Index:", record.index)
print("If Counter Type:", record.type)
print("If Counter Speed:", record.speed)
print("If Counter Direction:", record.direction)
print("If Counter Status:", record.status)
print("If Counter I Octets:", record.inputOctets)
print("If Counter I Packets:", record.inputPackets)
print("If Counter I Multicast:", record.inputMulticast)
print("If Counter I Broadcast:", record.inputBroadcast)
print("If Counter I Discards:", record.inputDiscarded)
print("If Counter I Errors:", record.inputErrors)
print("If Counter I Unknown:", record.inputUnknown)
print("If Counter O Octets:", record.outputOctets)
print("If Counter O Packets:", record.outputPackets)
print("If Counter O Multicast:", record.outputMulticast)
print("If Counter O Broadcast:", record.outputBroadcast)
print("If Counter O Discard:", record.outputDiscarded)
print("If Counter O Errors:", record.outputErrors)
print("If Counter Promiscuous:", record.promiscuous)

quit()

"""

while True:

    data, addr = sock.recvfrom(
        3000
    )  # 1386 bytes is the largest possible sFlow packet, by spec 3000 seems to be the number by practice
    sFlowData = sflow.sFlow(data)

    # Below this point is test code.

    print("")
    print("Source:", addr[0])
    print("length:", sFlowData.len)
    # print "DG Version:", sFlowData.dgVersion
    # print "Address Type:", sFlowData.addressType
    # print "Agent Address:", sFlowData.agentAddress
    # print "Sub Agent:", sFlowData.subAgent
    print("Sequence Number:", sFlowData.sequenceNumber)
    # print "System UpTime:", sFlowData.sysUpTime
    print("Number of Samples:", sFlowData.NumberSample)
    # print ""
    for i in range(sFlowData.NumberSample):
        # print "Sample Number:", i + 1
        # print "Sample Sequence:", sFlowData.sample[i].sequence
        # print "Sample Enterprise:", sFlowData.sample[i].enterprise
        # print "Sample Type:", sFlowData.sample[i].sampleType
        # print "Sample Length:", sFlowData.sample[i].len
        # print "Sample Source Type:", sFlowData.sample[i].sourceType
        # print "Sample Source Index:", sFlowData.sample[i].sourceIndex
        # print "Sample Rate:", sFlowData.sample[i].sampleRate
        # print "Sample Pool:", sFlowData.sample[i].samplePool
        # print "Sample Dropped Packets:", sFlowData.sample[i].droppedPackets
        # print "Sample Input Interface:", sFlowData.sample[i].input_interface
        # print "Sample Output Interface:", sFlowData.sample[i].output_interface
        # print "Sample Record Count:", sFlowData.sample[i].recordCount
        # print ""
        for j in range(sFlowData.sample[i].recordCount):
            # print "Record Header:", sFlowData.sample[i].record[j].header
            # print "Record Enterprise:", sFlowData.sample[i].record[j].enterprise
            # print "Record Sample Type:", sFlowData.sample[i].record[j].sampleType
            # print "Record Format:", sFlowData.sample[i].record[j].format
            # print "Record Length:", sFlowData.sample[i].record[j].len
            if sFlowData.sample[i].record[j].sampleType == 1:
                if sFlowData.sample[i].record[j].format == 1 and sFlowData.sample[i].record[j].enterprise == 0:
                    record = sflow.sFlowRawPacketHeader(sFlowData.sample[i].record[j].len, sFlowData.sample[i].record[j].data)
                    # print "Raw Packet Header Protocol:", record.headerProtocol
                    # print "Frame Length:", record.frameLength
                    # print "Payload Removed:", record.payloadRemoved
                    # print "Header Size:", record.headerSize
                    MACfrom = records.srcMAC.decode("utf-8")
                    MACfrom = ":".join(MACfrom[i : i + 2] for i in range(0, 11, 2))
                    print("SrcMac:", MACfrom)
                    MACto = records.dstMAC.decode("utf-8")
                    MACto = ":".join(MACto[i : i + 2] for i in range(0, 11, 2))
                    print("DstMAC:", MACto)
                    print("srcIp:", records.srcIp)
                    print("dstIp:", records.dstIp)
                    print("srcPort:", records.srcPort)
                    print("dstPort:", records.dstPort)
                    print("Len:", records.len)
                    print("Type:", records.type)
                    print("Flow 1")
                elif sFlowData.sample[i].record[j].format == 2 and sFlowData.sample[i].record[j].enterprise == 0:
                    record = sflow.sFlowEthernetFrame(sFlowData.sample[i].record[j].len, sFlowData.sample[i].record[j].data)
                    # print "Ethernet Frame Length:", record.frameLength
                    # print "Ethernet Frame src MAC:", record.srcMAC
                    # print "Ethernet Frame dst MAC:", record.dstMAC
                    # print "Ethernet Frame Record Type:", record.type
                    print("Flow 2")
                elif sFlowData.sample[i].record[j].format == 1001:
                    record = sflow.sFlowExtendedSwitch(sFlowData.sample[i].record[j].len, sFlowData.sample[i].record[j].data)
                    # print "Extended Switch:", record.srcVLAN
                    # print "Extended Switch:", record.srcPriority
                    # print "Extended Switch:", record.dstVLAN
                    # print "Extended Switch:", record.dstPriority
                    print("Flow 1001")
                else:
                    print("Flow Record Enterprise:", sFlowData.sample[i].record[j].enterprise)
                    print("Flow Record Type:", sFlowData.sample[i].record[j].format)
            elif sFlowData.sample[i].record[j].sampleType == 2:
                if sFlowData.sample[i].record[j].format == 1:
                    record = sflow.sFlowIfCounters(sFlowData.sample[i].record[j].len, sFlowData.sample[i].record[j].data)
                    print("If Counter Index:", record.index)
                    print("If Counter Type:", record.type)
                    print("If Counter Speed:", record.speed)
                    print("If Counter Direction:", record.direction)
                    print("If Counter Status:", record.status)
                    print("If Counter I Octets:", record.inputOctets)
                    print("If Counter I Packets:", record.inputPackets)
                    print("If Counter I Multicast:", record.inputMulticast)
                    print("If Counter I Broadcast:", record.inputBroadcast)
                    print("If Counter I Discards:", record.inputDiscarded)
                    print("If Counter I Errors:", record.inputErrors)
                    print("If Counter I Unknown:", record.inputUnknown)
                    print("If Counter O Octets:", record.outputOctets)
                    print("If Counter O Packets:", record.outputPackets)
                    print("If Counter O Multicast:", record.outputMulticast)
                    print("If Counter O Broadcast:", record.outputBroadcast)
                    print("If Counter O Discard:", record.outputDiscarded)
                    print("If Counter O Errors:", record.outputErrors)
                    print("If Counter Promiscuous:", record.promiscuous)
                    print(data)
                    print("Counter 1")
                elif sFlowData.sample[i].record[j].format == 2:
                    record = sflow.sFlowEthernetInterface(sFlowData.sample[i].record[j].len, sFlowData.sample[i].record[j].data)
                    # print "Ethernet Alignmet Error:", record.alignmentError
                    # print "Ethernet FCS Error:", record.fcsError
                    # print "Ethernet Single Collision Frames:", record.singleCollision
                    # print "Ethernet Multiple Collision Frames:", record.multipleCollision
                    # print "Ethernet SQE Test Error:", record.sqeTest
                    # print "Ethernet Deferred Transmissions:", record.deferred
                    # print "Ethernet Late Collisions:", record.lateCollision
                    # print "Ethernet Excessiove Collisions:", record.excessiveCollision
                    # print "Ethernet Internal Transmit Error:", record.internalTransmitError
                    # print "Ethernet Carrier Sense Error:", record.carrierSenseError
                    # print "Ethernet Frame Too Long:", record.frameTooLong
                    # print "Ethernet Internal Receive Error:", record.internalReceiveError
                    # print "Ethernet Symbol Error:", record.symbolError
                    # print "Counter 2"
                elif sFlowData.sample[i].record[j].format == 5:
                    record = sflow.sFlowVLAN(sFlowData.sample[i].record[j].len, sFlowData.sample[i].record[j].data)
                    # print "VLAN :", record.vlanID
                    # print "VLAN :", record.octets
                    # print "VLAN :", record.unicast
                    # print "VLAN :", record.multicast
                    # print "VLAN :", record.broadcast
                    # print "VLAN :", record.discard
                    print("Counter 5")
                elif sFlowData.sample[i].record[j].format == 1001:
                    record = sflow.sFlowProcessor(sFlowData.sample[i].record[j].len, sFlowData.sample[i].record[j].data)
                    # print "Processor :", record.cpu5s
                    # print "Processor :", record.cpu1m
                    # print "Processor :", record.cpu5m
                    # print "Processor :", record.totalMemory
                    # print "Processor :", record.freeMemory
                    print("Counter 1001")
                elif sFlowData.sample[i].record[j].format == 2000:
                    record = sflow.sFlowHostDescr(sFlowData.sample[i].record[j].len, sFlowData.sample[i].record[j].data)
                    print("Counter 2000")
                elif sFlowData.sample[i].record[j].format == 2001:
                    record = sflow.sFlowHostAdapters(sFlowData.sample[i].record[j].len, sFlowData.sample[i].record[j].data)
                    # print "Host Adpaters:", record.adapaters
                    print("Counter 2001")
                elif sFlowData.sample[i].record[j].format == 2002:
                    record = sflow.sFlowHostParent(sFlowData.sample[i].record[j].len, sFlowData.sample[i].record[j].data)
                    # print "Host Parent Container Type:", record.containerType
                    # print "Host Parent Container Index:", record.containerIndex
                    print("Counter 2002")
                elif sFlowData.sample[i].record[j].format == 2003:
                    record = sflow.sFlowHostCPU(sFlowData.sample[i].record[j].len, sFlowData.sample[i].record[j].data)
                    print("Counter 2003")
                elif sFlowData.sample[i].record[j].format == 2004:
                    record = sflow.sFlowHostMemory(sFlowData.sample[i].record[j].len, sFlowData.sample[i].record[j].data)
                    # print "Host Memory Total:", record.memTotal
                    # print "Host Memory Free:", record.memFree
                    # print "Host Memory Shared:", record.memShared
                    # print "Host Memory Buffers:", record.memBuffers
                    # print "Host Memory Cache:", record.memCache
                    # print "Host Swap Memory Total:", record.swapTotal
                    # print "Host Swap Memory Free:", record.swapFree
                    # print "Host Page In:", record.pageIn
                    # print "Host Page Out:", record.pageOut
                    # print "Host Swap Page In:", record.swapIn
                    # print "Host Swap Page Out:", record.swapOut
                    print("Counter 2004")
                elif sFlowData.sample[i].record[j].format == 2005:
                    record = sflow.sFlowHostDiskIO(sFlowData.sample[i].record[j].len, sFlowData.sample[i].record[j].data)
                    # print "Host disk:", record.diskTotal
                    # print "Host disk:", record.diskFree
                    # print "Host disk:", record.partMaxused
                    # print "Host disk:", record.read
                    # print "Host disk:", record.readByte
                    # print "Host disk:", record.readTime
                    # print "Host disk:", record.write
                    # print "Host disk:", record.writeByte
                    # print "Host disk:", record.writeTime
                    print("Counter 2005")
                elif sFlowData.sample[i].record[j].format == 2006:
                    record = sflow.sFlowHostNetIO(sFlowData.sample[i].record[j].len, sFlowData.sample[i].record[j].data)
                    print("Counter 2006")
                elif sFlowData.sample[i].record[j].format == 2007:
                    record = sflow.sFlowMib2IP(sFlowData.sample[i].record[j].len, sFlowData.sample[i].record[j].data)
                    print("Counter 2007")
                elif sFlowData.sample[i].record[j].format == 2008:
                    record = sflow.sFlowMib2ICMP(sFlowData.sample[i].record[j].len, sFlowData.sample[i].record[j].data)
                    print("Counter 2008")
                elif sFlowData.sample[i].record[j].format == 2009:
                    record = sflow.sFlowMib2TCP(sFlowData.sample[i].record[j].len, sFlowData.sample[i].record[j].data)
                    # print "TCP Algorithm:", record.algorithm
                    # print "TCP RTO Min:", record.rtoMin
                    # print "TCP RTO Max:", record.rtoMax
                    # print "TCP Max Connections:", record.maxConnection
                    # print "TCP Active Open:", record.activeOpen
                    # print "TCP Passive Open:", record.passiveOpen
                    # print "TCP Attempt Fail:", record.attemptFail
                    # print "TCP Established Reset:", record.establishedReset
                    # print "TCP Current Established:", record.currentEstablished
                    # print "TCP In Segments:", record.inSegment
                    # print "TCP Out Segments:", record.outSegment
                    # print "TCP Retransmit Segemnt:", record.retransmitSegment
                    # print "TCP In Error:", record.inError
                    # print "TCP Out Reset:", record.outReset
                    # print "TCP In C sum Error:", record.inCsumError
                    print("Counter 2009")
                elif sFlowData.sample[i].record[j].format == 2010:
                    record = sflow.sFlowMib2UDP(sFlowData.sample[i].record[j].len, sFlowData.sample[i].record[j].data)
                    # print "Counter 2010"
                    # print "UDP In Datagrams:", record.inDatagrams
                    # print "UDP No Ports:", record.noPorts
                    # print "UDP In Errors:", record.inErrors
                    # print "UDP Out Datagrams:", record.outDatagrams
                    # print "UDP Receive Buffer Error:", record.receiveBufferError
                    # print "UDP Send Buffer Error:", record.sendBufferError
                    # print "UDP In Check Sum Error:", record.inCheckSumError
                else:
                    print("Counter Record Enterprise:", sFlowData.sample[i].record[j].enterprise)
                    print("Counter Record Type:", sFlowData.sample[i].record[j].format)
