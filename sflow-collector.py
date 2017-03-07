#!/usr/bin/python
import socket
import struct
import uuid
import binascii

#The sFlow Collector is a set of classes for presenting sFlow data.

class sFlow:
    def __init__(self, dataGram):
        dataPosition = 0
        self.sample = []
        self.data = dataGram
        self.dgVersion = struct.unpack('>i', dataGram[0:4])[0]
        self.addressType = struct.unpack('>i', dataGram[4:8])[0]
        self.len = len(dataGram)
        if self.addressType == 1:
            self.agentAddress = socket.inet_ntoa(dataGram[8:12])
            self.subAgent = struct.unpack('>i', dataGram[12:16])[0]
            self.sequenceNumber = struct.unpack('>i', dataGram[16:20])[0]
            self.sysUpTime = struct.unpack('>i', dataGram[20:24])[0]
            self.NumberSample = struct.unpack('>i', dataGram[24:28])[0]
            dataPosition = 28
        elif self.addressType == 2:
            self.agentAddress = binascii.hexlify(dataGram[8:24]) #Temporary fix due to lack of IPv6 support on WIN32
            self.subAgent = struct.unpack('>i', dataGram[24:28])[0]
            self.sequenceNumber = struct.unpack('>i', dataGram[28:32])[0]
            self.sysUpTime = struct.unpack('>i', dataGram[32:36])[0]
            self.NumberSample = struct.unpack('>i', dataGram[36:40])[0]
            dataPosition = 40
        else:
            self.agentAddress = 0
            self.subAgent = 0
            self.sequenceNumber = 0
            self.sysUpTime = 0
            self.NumberSample = 0
        if self.NumberSample > 0:
            for i in range(self.NumberSample):
                SampleHeader = dataGram[(dataPosition):(dataPosition + 4)]
                SampleSize = struct.unpack('>i', dataGram[(dataPosition + 4):(dataPosition + 8)])[0]
                SampleDataGram = dataGram[(dataPosition + 8):(dataPosition + SampleSize + 8)]
                
                self.sample.append(sFlowSample(SampleHeader, SampleSize, SampleDataGram))
                dataPosition = dataPosition + 8 + SampleSize

class sFlowSample:
    def __init__(self, header, sampleSize, dataGram):
        self.record = []
        self.data = dataGram
        SampleHeader = struct.unpack('>i', header)[0]
        
        self.sequence = struct.unpack('>i', dataGram[0:4])[0]
        SampleSource = struct.unpack('>i', dataGram[4:8])[0]
        
        self.enterprise = (SampleHeader & 4294963200)/4096
        self.sampleType = (SampleHeader & 4095) # 0 sample_data / 1 flow_data (single) / 2 counter_data (single) / 3 flow_data (expanded) / 4 counter_data (expanded)
        self.len = sampleSize
        
        self.sourceType = (SampleSource & 4278190080)/16777216
        self.sourceIndex = (SampleSource & 16777215)
        
        dataPosition = 8
        if self.sampleType == 1: #Flow
                self.sampleRate = struct.unpack('>i', dataGram[(dataPosition):(dataPosition + 4)])[0]
                self.samplePool = struct.unpack('>i', dataGram[(dataPosition + 4):(dataPosition + 8)])[0]
                self.droppedPackets = struct.unpack('>i', dataGram[(dataPosition + 8):(dataPosition + 12)])[0]
                self.inputInterface = struct.unpack('>i', dataGram[(dataPosition + 12):(dataPosition + 16)])[0]
                self.outputInterface = struct.unpack('>i', dataGram[(dataPosition + 16):(dataPosition + 20)])[0]
                self.recordCount = struct.unpack('>i', dataGram[(dataPosition + 20):(dataPosition + 24)])[0]
                dataPosition = 32
                
                for i in range(self.recordCount):
                    RecordHeader = struct.unpack('>i', dataGram[(dataPosition):(dataPosition + 4)])[0]
                    RecordSize = struct.unpack('>i', dataGram[(dataPosition + 4):(dataPosition + 8)])[0]
                    RecordData = dataGram[(dataPosition + 8):(dataPosition + RecordSize +8)]
                    self.record.append(sFlowRecord(RecordHeader, RecordSize, self.sampleType, RecordData))
                    dataPosition = dataPosition + 8 + RecordSize
                
        elif self.sampleType == 2: #Counters
                self.recordCount = struct.unpack('>i', dataGram[(dataPosition):(dataPosition + 4)])[0]
                self.sampleRate = 0
                self.samplePool = 0
                self.droppedPackets = 0
                self.inputInterface = 0
                self.outputInterface = 0
                dataPosition = 12

                for i in range(self.recordCount):
                    RecordHeader = struct.unpack('>i', dataGram[(dataPosition):(dataPosition + 4)])[0]
                    RecordSize = struct.unpack('>i', dataGram[(dataPosition + 4):(dataPosition + 8)])[0]
                    RecordData = dataGram[(dataPosition + 8):(dataPosition + RecordSize + 8)]
                    self.record.append(sFlowRecord(RecordHeader, RecordSize, self.sampleType, RecordData))
                    dataPosition = dataPosition + 8 + RecordSize
        else:
                self.recordCount = 0
                self.sampleRate = 0
                self.samplePool = 0
                self.droppedPackets = 0
                self.inputInterface = 0
                self.outputInterface = 0
                

            
class sFlowRecord:
    def __init__(self, header, length, sampleType, dataGram):
        self.header = header
        self.enterprise = (self.header & 4294901760)/4096
        self.format = (self.header & 4095) 
        self.len = length
        self.sampleType = sampleType
        self.data = dataGram


        

class sFlowHostDisc: #2-2000
    def __init__(self, length, dataGram):
        self.length = length
        self.data = dataGram
        dataPosition = 4
        nameLength = struct.unpack('>i', dataGram[0:4])[0]
        self.hostName = dataGram[dataPosition:(dataPosition + nameLength)].decode("utf-8")
        if nameLength % 4 <> 0:
            nameLength = (((nameLength // 4)+1)*4)
        dataPosition = dataPosition + nameLength
        self.uuid = uuid.UUID(binascii.hexlify(dataGram[dataPosition:(dataPosition + 16)]))
        dataPosition = dataPosition + 16
        self.machineType = struct.unpack('>i', dataGram[dataPosition:(dataPosition + 4)])[0]
        dataPosition = dataPosition + 4
        self.osName = struct.unpack('>i', dataGram[dataPosition:(dataPosition + 4)])[0]
        dataPosition = dataPosition + 4
        osReleaseLength = struct.unpack('>i', dataGram[dataPosition:(dataPosition + 4)])[0]
        dataPosition = dataPosition + 4
        self.osRelease = dataGram[dataPosition:(dataPosition + osReleaseLength)].decode("utf-8")

class sFlowHostCPU: #2-2003
    def __init__(self, length, dataGram):
        self.length = length
        self.data = dataGram
        self.avgLoad1 = struct.unpack('>f', dataGram[0:4])[0]
        self.avgLoad5 = struct.unpack('>f', dataGram[4:8])[0]
        self.avgLoad15 = struct.unpack('>f', dataGram[8:12])[0]
        self.runProcess = struct.unpack('>i', dataGram[12:16])[0]
        self.totalProcess = struct.unpack('>i', dataGram[16:20])[0]
        self.numCPU = struct.unpack('>i', dataGram[20:24])[0]
        self.mhz = struct.unpack('>i', dataGram[24:28])[0]
        self.uptime = struct.unpack('>i', dataGram[28:32])[0]
        self.timeUser = struct.unpack('>i', dataGram[32:36])[0]
        self.timeNices = struct.unpack('>i', dataGram[36:40])[0]
        self.timeKennal = struct.unpack('>i', dataGram[40:44])[0]
        self.timeIdle = struct.unpack('>i', dataGram[44:48])[0]
        self.timeIO = struct.unpack('>i', dataGram[48:52])[0]
        self.timeInterrupt = struct.unpack('>i', dataGram[52:56])[0]
        self.timeSoftInterrupt = struct.unpack('>i', dataGram[56:60])[0]
        self.interrupt = struct.unpack('>i', dataGram[60:64])[0]
        self.contextSwitch = struct.unpack('>i', dataGram[64:68])[0]
        self.virtualInstance = struct.unpack('>i', dataGram[68:72])[0]
        self.guestOS = struct.unpack('>i', dataGram[72:76])[0]
        self.guestNice = struct.unpack('>i', dataGram[76:80])[0]
        
        
     

UDP_IP = "0.0.0.0"
UDP_PORT = 6343

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

while True:
                                                 
    data, addr = sock.recvfrom(1386) # 1386 bytes is the largest possible sFlow packet
    sFlowData = sFlow(data)

    print ""
    print "Source:", addr[0]
    #print "length:", sFlowData.len
    #print "DG Version:", sFlowData.dgVersion
    #print "Address Type:", sFlowData.addressType
    print "Agent Address:", sFlowData.agentAddress
    #print "Sub Agent:", sFlowData.subAgent
    #print "Sequence Number:", sFlowData.sequenceNumber
    #print "System UpTime:", sFlowData.sysUpTime
    #print "Number of Samples:", sFlowData.NumberSample
    print ""
    for i in range(sFlowData.NumberSample):
        #print "Sample Number:", i + 1
        #print "Sample Sequence:", sFlowData.sample[i].sequence
        #print "Sample Enterprise:", sFlowData.sample[i].enterprise
        #print "Sample Type:", sFlowData.sample[i].sampleType
        #print "Sample Length:", sFlowData.sample[i].len
        #print "Sample Source Type:", sFlowData.sample[i].sourceType
        #print "Sample Source Index:", sFlowData.sample[i].sourceIndex
        #print "Sample Rate:", sFlowData.sample[i].sampleRate
        #print "Sample Pool:", sFlowData.sample[i].samplePool
        #print "Sample Dropped Packets:", sFlowData.sample[i].droppedPackets
        #print "Sample Input Interface:", sFlowData.sample[i].inputInterface
        #print "Sample Output Interface:", sFlowData.sample[i].outputInterface
        #print "Sample Record Count:", sFlowData.sample[i].recordCount
        #print ""
        for j in range(sFlowData.sample[i].recordCount):
            #print "Record Header:", sFlowData.sample[i].record[j].header
            #print "Record Enterprise:", sFlowData.sample[i].record[j].enterprise
            print "Record Sample Type:", sFlowData.sample[i].record[j].sampleType
            print "Record Format:", sFlowData.sample[i].record[j].format
            #print "Record Length:", sFlowData.sample[i].record[j].len
            print ""
                    




                
