#!/usr/bin/python
import socket
import sflow

# Basic Listener

UDP_IP = "0.0.0.0"
UDP_PORT = 6343

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

while True:

    data, addr = sock.recvfrom(
        3000
    )  # 1386 bytes is the largest possible sFlow packet, by spec 3000 seems to be the number by practice
    sFlowData = sflow.sFlow(data)

    # Below this point is test code.

    # print()
    print("Source:", addr[0])
    # print("length:", sFlowData.len)
    # print("DG Version:", sFlowData.dgVersion)
    # print("Address Type:", sFlowData.addressType)
    # print("Agent Address:", sFlowData.agentAddress)
    # print("Sub Agent:", sFlowData.subAgent)
    # print("Sequence Number:", sFlowData.sequenceNumber)
    # print("System UpTime:", sFlowData.sysUpTime)
    # print("Number of Samples:", sFlowData.NumberSample)
    # print()
    for i in range(sFlowData.NumberSample):
        # print "Sample Number:", i + 1
        # print("Sample Sequence:", sFlowData.samples[i].sequence)
        # print("Sample Enterprise:", sFlowData.samples[i].enterprise)
        # print("Sample Type:", sFlowData.samples[i].sampleType)
        # print("Sample Length:", sFlowData.samples[i].len)
        # print("Sample Source Type:", sFlowData.samples[i].sourceType)
        # print("Sample Source Index:", sFlowData.samples[i].sourceIndex)
        # print("Sample Rate:", sFlowData.samples[i].sampleRate)
        # print("Sample Pool:", sFlowData.samples[i].samplePool)
        # print("Sample Dropped Packets:", sFlowData.samples[i].droppedPackets)
        # print("Sample Input Interface:", sFlowData.samples[i].inputInterface)
        # print("Sample Output Interface:", sFlowData.samples[i].outputInterface)
        # print "Sample Record Count:", sFlowData.samples[i].recordCount
        # print()
        for j in range(sFlowData.samples[i].recordCount):
            # record = sFlowData.samples[i].records[j].data
            print("Sample Type", sFlowData.samples[i].records[j].sampleType)
            print("Sample Record Enterprise:", sFlowData.samples[i].records[j].enterprise)
            print("Sample Record Type:", sFlowData.samples[i].records[j].format)
            print(repr(sFlowData.samples[i].records[j].data))
