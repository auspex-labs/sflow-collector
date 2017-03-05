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
                SampleSize = struct.unpack('>i', dataGram[(dataPosition + 4):(dataPosition + 8)])[0]
                self.sample.append(sFlowSample(dataGram[(dataPosition):(dataPosition + 4)], SampleSize, dataGram[(dataPosition + 8):(dataPosition + SampleSize + 8)]))
                dataPosition = dataPosition + 8 + SampleSize
             



class sFlowSample:
    def __init__(self, header, sampleSize, dataGram):
        self.record = []
        self.data = dataGram
        SampleHeader = struct.unpack('>i', header)[0]
        SampleSource = struct.unpack('>i', dataGram[4:8])[0]
        self.enterprise = (SampleHeader & 4294963200)/4096
        self.sampleType = (SampleHeader & 4095) # 0 sample_data / 1 flow_data (single) / 2 counter_data (single) / 3 flow_data (expanded) / 4 counter_data (expanded
        self.length = sampleSize
        self.sequence = struct.unpack('>i', dataGram[0:4])[0]
        if self.sampleType == 0:

        elif self.sampleType == 1:

        elif self.sampleType == 2:
                self.sourceType = (SampleSource & 4278190080)/16777216
                self.sourceIndex = (SampleSource & 16777215)
                self.recordCount = struct.unpack('>i', dataGram[8:12])[0]
                dataPosition = 12
                    for i in range(self.recordCount):
                        RecordSize = struct.unpack('>i', dataGram[(dataPosition + 4):(dataPosition + 8)])[0]
                        self.record.append(sFlowCounterRecord(dataGram[(dataPosition):(dataPosition + 4)], RecordSize, self.sampleType, dataGram[(dataPosition + 8):(dataPosition + RecordSize +8)]))
                        dataPosition = dataPosition + 8 + RecordSize
        elif self.sampleType == 3:

        elif self.sampleType == 4:
                self.sourceType = (SampleSource & 4278190080)/16777216
                self.sourceIndex = (SampleSource & 16777215)
                self.recordCount = struct.unpack('>i', dataGram[8:12])[0]
                dataPosition = 12
                    for i in range(self.recordCount):
                        RecordSize = struct.unpack('>i', dataGram[(dataPosition + 4):(dataPosition + 8)])[0]
                        self.record.append(sFlowCounterRecord(dataGram[(dataPosition):(dataPosition + 4)], RecordSize, self.sampleType, dataGram[(dataPosition + 8):(dataPosition + RecordSize +8)]))
                        dataPosition = dataPosition + 8 + RecordSize
        else:
            
class sFlowCounterRecord:
    def __init__(self, header, length, sampleType, dataGram):
        RecordHeader = struct.unpack('>i', header)[0]
        self.header = header
        self.enterprise = (RecordHeader & 4294901760)/65536
        self.format = (RecordHeader & 65535) 
        self.length = length
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
    print "DG Version:", sFlowData.dgVersion
    print "Address Type:", sFlowData.addressType
    print "Agent Address:", sFlowData.agentAddress
    #print "Sub Agent:", sFlowData.subAgent
    print "Sequence Number:", sFlowData.sequenceNumber
    #print "System UpTime:", sFlowData.sysUpTime
    print "Number of Samples:", sFlowData.NumberSample
    #print ""
    for i in range(sFlowData.NumberSample):
        print "Sample Number:", i + 1
        #print "Sample Enterprise:", sFlowData.sample[i].enterprise
        print "Sample Type:", sFlowData.sample[i].sampleType
        print "Sample Sequence:", sFlowData.sample[i].sequence
        print "Sample Record Count:", sFlowData.sample[i].recordCount
        #print ""
        #for j in range(sFlowData.sample[i].recordCount):
            #print "Record Enterprise:", sFlowData.sample[i].record[j].enterprise
            #print "Record Format:", sFlowData.sample[i].record[j].format
            #if sFlowData.sample[i].sampleType == 2:
                #if sFlowData.sample[i].record[j].format == 2000:
                    #element = sFlowHostDisc(sFlowData.sample[i].record[j].length, sFlowData.sample[i].record[j].data)
                    #print "Host Name:", element.hostName
                    #print "UUID:", element.uuid
                    #print "Machine Type:", element.machineType
                    #print "OS Name:", element.osName
                    #print "OS Release:", element.osRelease
                #elif sFlowData.sample[i].record[j].format == 2003:
                    #element = sFlowHostCPU(sFlowData.sample[i].record[j].length, sFlowData.sample[i].record[j].data)
                    #print "Processes:", element.totalProcess
                    #print "Uptime:", element.uptime
                    




                
