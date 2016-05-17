import socket
import struct
import uuid
import binascii

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
        self.sampleType = (SampleHeader & 4095)
        self.length = sampleSize
        self.sequence = struct.unpack('>i', dataGram[0:4])[0]
        self.sourceType = (SampleSource & 4278190080)/16777216
        self.sourceIndex = (SampleSource & 16777215)
        self.recordCount = struct.unpack('>i', dataGram[8:12])[0]
        dataPosition = 12
        for i in range(self.recordCount):
            RecordSize = struct.unpack('>i', dataGram[(dataPosition + 4):(dataPosition + 8)])[0]
            self.record.append(sFlowRecord(dataGram[(dataPosition):(dataPosition + 4)], RecordSize, self.sampleType, dataGram[(dataPosition + 8):(dataPosition + RecordSize +8)]))
            dataPosition = dataPosition + 8 + RecordSize
            
class sFlowRecord:
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

        

UDP_IP = ''
UDP_PORT = 6343

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

while True:
                                                 
    data, addr = sock.recvfrom(2000)
    sFlowData = sFlow(data)

    print ""
    print "Source:", addr[0]
    #print "length:", sFlowData.len
    print "DG Version:", sFlowData.dgVersion
    print "Address Type:", sFlowData.addressType
    print "Agent Address:", sFlowData.agentAddress
    #print "Sub Agent:", sFlowData.subAgent
    #print "Sequence Number:", sFlowData.sequenceNumber
    #print "System UpTime:", sFlowData.sysUpTime
    #print "Number of Samples:", sFlowData.NumberSample
    #print ""
    for i in range(sFlowData.NumberSample):
        print "Sample Number:", i + 1
        #print "Sample Enterprise:", sFlowData.sample[i].enterprise
        print "Sample Type:", sFlowData.sample[i].sampleType
        #print "Sample Sequence:", sFlowData.sample[i].sequence
        print "Sample Record Count:", sFlowData.sample[i].recordCount
        #print ""
        for j in range(sFlowData.sample[i].recordCount):
            #print "Record Enterprise:", sFlowData.sample[i].record[j].enterprise
            print "Record Format:", sFlowData.sample[i].record[j].format
            if sFlowData.sample[i].sampleType == 2:
                if sFlowData.sample[i].record[j].format == 2000:
                    element = sFlowHostDisc(sFlowData.sample[i].record[j].length, sFlowData.sample[i].record[j].data)
                    print "Host Name:", element.hostName
                    print "UUID:", element.uuid
                    print "Machine Type:", element.machineType
                    print "OS Name:", element.osName
                    print "OS Release:", element.osRelease




                
