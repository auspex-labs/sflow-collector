import socket
import pprint

import sflow

# Basic Listener

UDP_IP = "127.0.0.1"
UDP_PORT = 6343

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

while True:

    data, addr = sock.recvfrom(
        3000
    )  # 1386 bytes is the largest possible sFlow packet, by spec 3000 seems to be the number by practice
    sflow_data = sflow.sFlow(data)

    # Below this point is test code.

    # print(".", end="")
    # print("Source:", addr[0])
    # print("length:", sflow_data.len)
    # print("DG Version:", sflow_data.dgVersion)
    # print("Address Type:", sflow_data.addressType)
    # print("Agent Address:", sflow_data.agentAddress)
    # print("Sub Agent:", sflow_data.subAgent)
    # print("Sequence Number:", sflow_data.sequenceNumber)
    # print("System UpTime:", sflow_data.sysUpTime)
    # print("Number of Samples:", sflow_data.NumberSample)
    # print()
    for i in range(sflow_data.NumberSample):
        # print "Sample Number:", i + 1
        # print("Sample Sequence:", sflow_data.samples[i].sequence)
        # print("Sample Enterprise:", sflow_data.samples[i].enterprise)
        # print("Sample Type:", sflow_data.samples[i].sample_type)
        # print("Sample Length:", sflow_data.samples[i].len)
        # print("Sample Source Type:", sflow_data.samples[i].sourceType)
        # print("Sample Source Index:", sflow_data.samples[i].sourceIndex)
        # print("Sample Rate:", sflow_data.samples[i].sampleRate)
        # print("Sample Pool:", sflow_data.samples[i].samplePool)
        # print("Sample Dropped Packets:", sflow_data.samples[i].droppedPackets)
        # print("Sample Input Interface:", sflow_data.samples[i].input_interface)
        # print("Sample Output Interface:", sflow_data.samples[i].output_interface)
        # print "Sample Record Count:", sflow_data.samples[i].recordCount
        # print()
        for j in range(sflow_data.samples[i].recordCount):
            # record = sflow_data.samples[i].records[j].data
            # print("Sample Type:", sflow_data.samples[i].records[j].sample_type, end ="")
            # print(" Sample Record Enterprise:", sflow_data.samples[i].records[j].enterprise, end ="")
            # print(" Sample Record Type:", sflow_data.samples[i].records[j].format)
            # print(repr(sflow_data.samples[i].records[j].record))
            pprint.pprint(vars(sflow_data.samples[i].records[j].record))
