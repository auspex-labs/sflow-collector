#!/usr/bin/python
import socket
import struct
import uuid
import binascii

# The sFlow Collector is a class for parsing sFlow data.

# sFlow datagrams contain a header, which may contain samples which may contain one or more samples.
#
# The datagram may not contain a sample, but if it does there will be at least on record.
#
# The records may have different formats.

#IDEA: Is the raw data for each block actually needed? What is the cost for preserving them?

class sFlow:
    def __init__(self, dataGram):

        # sFlow Sample class.

        class Sample:
            def __init__(self, header, sampleSize, dataGram):

            	#sFlow Record class.

                class Record:
                    def __init__(self, header, length, sampleType, dataGram):
                        self.header = header
                        self.enterprise = (self.header & 4294901760)/4096
                        self.format = (self.header & 4095) 
                        self.len = length
                        self.sampleType = sampleType
                        self.data = dataGram
                
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

                # 
                
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
                            self.record.append(Record(RecordHeader, RecordSize, self.sampleType, RecordData))
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
                            self.record.append(Record(RecordHeader, RecordSize, self.sampleType, RecordData))
                            dataPosition = dataPosition + 8 + RecordSize
                else:
                        self.recordCount = 0
                        self.sampleRate = 0
                        self.samplePool = 0
                        self.droppedPackets = 0
                        self.inputInterface = 0
                        self.outputInterface = 0


        # Begin sFlow
        
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
                
                self.sample.append(Sample(SampleHeader, SampleSize, SampleDataGram))
                dataPosition = dataPosition + 8 + SampleSize


#IDEA: Sanity check for the fixed length records could be implimented with a simple value check. 17-03-07

#Flow Record Types

class sFlowRawPacketHeader: #1-1  (Variable)
    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.headerProtocol = struct.unpack('>i', dataGram[0:4])[0]
        self.frameLength = struct.unpack('>i', dataGram[4:8])[0]
        self.payloadRemoved = struct.unpack('>i', dataGram[8:12])[0]
        headerSize = struct.unpack('>i', dataGram[12:16])[0]
        self.headerSize = headerSize
        self.header = dataGram[16:(headerSize + 16)] #Need a class for parsing the header information.
        
class sFlowEthernetFrame: #1-2  (24 bytes)
    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.frameLength = struct.unpack('>i', dataGram[0:4])[0]
        self.srcMAC = binascii.hexlify(dataGram[4:12])
        self.dstMAC = binascii.hexlify(dataGram[12:20])
        self.type = struct.unpack('>i', dataGram[20:24])[0]

class sFlowExtendedSwitch: #1-1001 (16 bytes)
    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.srcVLAN = struct.unpack('>i', dataGram[0:4])[0]
        self.srcPriority = struct.unpack('>i', dataGram[4:8])[0]
        self.dstVLAN = struct.unpack('>i', dataGram[8:12])[0]
        self.dstPriority = struct.unpack('>i', dataGram[12:16])[0]

#Counter Record Types

class sFlowIfCounter: #2-1 (88 bytes)
    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.index = struct.unpack('>i', dataGram[0:4])[0]
        self.type = struct.unpack('>i', dataGram[4:8])[0]
        self.speed = struct.unpack('>q', dataGram[8:16])[0] #64-bit
        self.direction = struct.unpack('>i', dataGram[16:20])[0]
        self.status = struct.unpack('>i', dataGram[20:24])[0] #This is really a 2-bit value
        self.inputOctets = struct.unpack('>q', dataGram[24:32])[0] #64-bit
        self.inputPackets = struct.unpack('>i', dataGram[32:36])[0]
        self.inputMulticast = struct.unpack('>i', dataGram[36:40])[0]
        self.inputBroadcast = struct.unpack('>i', dataGram[40:44])[0]
        self.inputDiscarded = struct.unpack('>i', dataGram[44:48])[0]
        self.inputErrors = struct.unpack('>i', dataGram[48:52])[0]
        self.inputUnknown = struct.unpack('>i', dataGram[52:56])[0]
        self.outputOctets = struct.unpack('>q', dataGram[56:64])[0] #64-bit
        self.outputPackets = struct.unpack('>i', dataGram[64:68])[0]
        self.outputMulticast = struct.unpack('>i', dataGram[68:72])[0]
        self.outputBroadcast = struct.unpack('>i', dataGram[72:76])[0]
        self.outputDiscarded = struct.unpack('>i', dataGram[76:80])[0]
        self.outputErrors = struct.unpack('>i', dataGram[80:84])[0]
        self.promiscuous = struct.unpack('>i', dataGram[84:88])[0]

class sFlowEthernetInterface: #2-2 (52 bytes)
    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.alignmentError = struct.unpack('>i', dataGram[0:4])[0]
        self.fcsError = struct.unpack('>i', dataGram[4:8])[0]
        self.singleCollision = struct.unpack('>i', dataGram[8:12])[0]
        self.multipleCollision = struct.unpack('>i', dataGram[12:16])[0]
        self.sqeTest = struct.unpack('>i', dataGram[16:20])[0]
        self.deferred = struct.unpack('>i', dataGram[20:24])[0]
        self.lateCollision = struct.unpack('>i', dataGram[24:28])[0]
        self.excessiveCollision = struct.unpack('>i', dataGram[28:32])[0]
        self.internalTransmitError = struct.unpack('>i', dataGram[32:36])[0]
        self.carrierSenseError = struct.unpack('>i', dataGram[36:40])[0]
        self.frameTooLong = struct.unpack('>i', dataGram[40:44])[0]
        self.internalReceiveError = struct.unpack('>i', dataGram[44:48])[0]
        self.symbolError = struct.unpack('>i', dataGram[48:52])[0]

class sFlowVLAN: #2-5 (28 bytes)
    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.vlanID = struct.unpack('>i', dataGram[0:4])[0]
        self.octets = struct.unpack('>q', dataGram[4:12])[0] #64-bit
        self.unicast = struct.unpack('>i', dataGram[12:16])[0]
        self.multicast = struct.unpack('>i', dataGram[16:20])[0]
        self.broadcast = struct.unpack('>i', dataGram[20:24])[0]
        self.discard = struct.unpack('>i', dataGram[24:28])[0]

class sFlowProcessor: #2-1001 (28 bytes)
    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.cpu5s = struct.unpack('>i', dataGram[0:4])[0]
        self.cpu1m = struct.unpack('>i', dataGram[4:8])[0] 
        self.cpu5m = struct.unpack('>i', dataGram[8:12])[0]
        self.totalMemory = struct.unpack('>q', dataGram[12:20])[0] #64-bit
        self.freeMemory = struct.unpack('>q', dataGram[20:28])[0] #64-bit       

class sFlowHostDisc: #2-2000 (variable length)
    def __init__(self, length, dataGram):
        self.len = length
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

class sFlowHostAdapters: #2-2001 (4 bytes)
    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.adapaters = struct.unpack('>i', dataGram[0:4])[0]
    

class sFlowHostCPU: #2-2003 (80 bytes)
    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.avgLoad1 = struct.unpack('>f', dataGram[0:4])[0] #Floating Point
        self.avgLoad5 = struct.unpack('>f', dataGram[4:8])[0] #Floating Point
        self.avgLoad15 = struct.unpack('>f', dataGram[8:12])[0] #Floating Point
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

class sFlowHostMemory: #2-2004 (72 bytes)
    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.memTotal = struct.unpack('>q', dataGram[0:8])[0] #64-bit
        self.memFree = struct.unpack('>q', dataGram[8:16])[0] #64-bit
        self.memShared = struct.unpack('>q', dataGram[16:24])[0] #64-bit
        self.memBuffers = struct.unpack('>q', dataGram[24:32])[0] #64-bit
        self.memCache = struct.unpack('>q', dataGram[32:40])[0] #64-bit
        self.swapTotal = struct.unpack('>q', dataGram[40:48])[0] #64-bit
        self.swapFree = struct.unpack('>q', dataGram[48:56])[0] #64-bit
        self.pageIn = struct.unpack('>i', dataGram[56:60])[0]
        self.pageOut = struct.unpack('>i', dataGram[60:64])[0]
        self.swapIn = struct.unpack('>i', dataGram[64:68])[0]
        self.swapOut = struct.unpack('>i', dataGram[68:72])[0]

class sFlowHostDiskIO: #2-2005 (52 bytes)
    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.diskTotal = struct.unpack('>q', dataGram[0:8])[0] #64-bit
        self.diskFree = struct.unpack('>q', dataGram[8:16])[0] #64-bit
        self.partMaxused = (struct.unpack('>i', dataGram[16:20])[0])/ float(100)
        self.read = struct.unpack('>i', dataGram[20:24])[0]
        self.readByte = struct.unpack('>q', dataGram[24:32])[0] #64-bit
        self.readTime = struct.unpack('>i', dataGram[32:36])[0]
        self.write = struct.unpack('>i', dataGram[36:40])[0]
        self.writeByte = struct.unpack('>q', dataGram[40:48])[0] #64-bit
        self.writeTime = struct.unpack('>i', dataGram[48:52])[0]

class sFlowHostNetIO: #2-2006 (40 bytes)
    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.inByte = struct.unpack('>q', dataGram[0:8])[0] #64-bit
        self.inPacket = struct.unpack('>i', dataGram[8:12])[0]
        self.inError = struct.unpack('>i', dataGram[12:16])[0]
        self.inDrop = struct.unpack('>i', dataGram[16:20])[0]
        self.outByte = struct.unpack('>q', dataGram[20:28])[0] #64-bit
        self.outPacket = struct.unpack('>i', dataGram[28:32])[0]
        self.outError = struct.unpack('>i', dataGram[32:36])[0]
        self.outDrop = struct.unpack('>i', dataGram[36:40])[0]

class sFlowMib2IP: #2-2007 (76 bytes)
    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.forwarding = struct.unpack('>i', dataGram[0:4])[0]
        self.defaultTTL = struct.unpack('>i', dataGram[4:8])[0]
        self.inReceives = struct.unpack('>i', dataGram[8:12])[0]
        self.inHeaderErrors = struct.unpack('>i', dataGram[12:16])[0]
        self.inAddressErrors = struct.unpack('>i', dataGram[16:20])[0]
        self.inForwardDatagrams = struct.unpack('>i', dataGram[20:24])[0]
        self.inUnknownProtocols = struct.unpack('>i', dataGram[24:28])[0]
        self.inDiscards = struct.unpack('>i', dataGram[28:32])[0]
        self.inDelivers = struct.unpack('>i', dataGram[32:36])[0]
        self.outRequests = struct.unpack('>i', dataGram[36:40])[0]
        self.outDiscards = struct.unpack('>i', dataGram[40:44])[0]
        self.outNoRoutes = struct.unpack('>i', dataGram[44:48])[0]
        self.reassemblyTimeout = struct.unpack('>i', dataGram[48:52])[0]
        self.reassemblyRequired = struct.unpack('>i', dataGram[52:56])[0]
        self.reassemblyOkay = struct.unpack('>i', dataGram[56:60])[0]
        self.reassemblyFail = struct.unpack('>i', dataGram[60:64])[0]
        self.fragmentOkay = struct.unpack('>i', dataGram[64:68])[0]
        self.fragmentFail = struct.unpack('>i', dataGram[68:72])[0]
        self.fragmentCreate = struct.unpack('>i', dataGram[72:76])[0]
        
class sFlowMib2ICMP: #2-2008 (100 bytes)
    def __init__(self, length, dataGram):
        self.len = length 
        self.data = dataGram
        self.inMessage = struct.unpack('>i', dataGram[0:4])[0]
        self.inError = struct.unpack('>i', dataGram[4:8])[0]
        self.inDestinationUnreachable = struct.unpack('>i', dataGram[8:12])[0]
        self.inTimeExceeded = struct.unpack('>i', dataGram[12:16])[0]
        self.inParameterProblem = struct.unpack('>i', dataGram[16:20])[0]
        self.inSourceQuence = struct.unpack('>i', dataGram[20:24])[0]
        self.inRedirect = struct.unpack('>i', dataGram[24:28])[0]
        self.inEcho = struct.unpack('>i', dataGram[28:32])[0]
        self.inEchoReply = struct.unpack('>i', dataGram[32:36])[0]
        self.inTimestamp = struct.unpack('>i', dataGram[36:40])[0]
        self.inAddressMask = struct.unpack('>i', dataGram[40:44])[0]
        self.inAddressMaskReply = struct.unpack('>i', dataGram[44:48])[0]
        self.outMessage = struct.unpack('>i', dataGram[48:52])[0]
        self.outError = struct.unpack('>i', dataGram[52:56])[0]
        self.outDestinationUnreachable = struct.unpack('>i', dataGram[56:60])[0]
        self.outTimeExceeded = struct.unpack('>i', dataGram[60:64])[0]
        self.outParameterProblem = struct.unpack('>i', dataGram[64:68])[0]
        self.outSourceQuence = struct.unpack('>i', dataGram[68:72])[0]
        self.outRedirect = struct.unpack('>i', dataGram[72:76])[0]
        self.outEcho = struct.unpack('>i', dataGram[76:80])[0]
        self.outEchoReply = struct.unpack('>i', dataGram[80:84])[0]
        self.outTimestamp = struct.unpack('>i', dataGram[84:88])[0]
        self.outTimestampReply = struct.unpack('>i', dataGram[88:92])[0]
        self.outAddressMask = struct.unpack('>i', dataGram[92:96])[0]
        self.outAddressMaskReplay = struct.unpack('>i', dataGram[96:100])[0]
        
class sFlowMib2TCP: #2-2009 (60 bytes)
    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.algorithm = struct.unpack('>i', dataGram[0:4])[0]
        self.rtoMin = struct.unpack('>i', dataGram[4:8])[0]
        self.rtoMax = struct.unpack('>i', dataGram[8:12])[0]
        self.maxConnection = struct.unpack('>i', dataGram[12:16])[0]
        self.activeOpen = struct.unpack('>i', dataGram[16:20])[0]
        self.passiveOpen = struct.unpack('>i', dataGram[20:24])[0]
        self.attemptFail = struct.unpack('>i', dataGram[24:28])[0]
        self.establishedReset = struct.unpack('>i', dataGram[28:32])[0]
        self.currentEstablished = struct.unpack('>i', dataGram[32:36])[0]
        self.inSegment = struct.unpack('>i', dataGram[36:40])[0]
        self.outSegment = struct.unpack('>i', dataGram[40:44])[0]
        self.retransmitSegment = struct.unpack('>i', dataGram[44:48])[0]
        self.inError = struct.unpack('>i', dataGram[48:52])[0]
        self.outReset = struct.unpack('>i', dataGram[52:56])[0]
        self.inCsumError = struct.unpack('>i', dataGram[56:60])[0]
        
class sFlowMib2UDP: #2-2010 (28 bytes)
    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.inDatagrams = struct.unpack('>i', dataGram[0:4])[0]
        self.noPorts = struct.unpack('>i', dataGram[4:8])[0]
        self.inErrors = struct.unpack('>i', dataGram[8:12])[0]
        self.outDatagrams = struct.unpack('>i', dataGram[12:16])[0]
        self.receiveBufferError = struct.unpack('>i', dataGram[16:20])[0]
        self.sendBufferError = struct.unpack('>i', dataGram[20:24])[0]
        self.inCheckSumError = struct.unpack('>i', dataGram[24:28])[0]
        
        
        
     

UDP_IP = "0.0.0.0"
UDP_PORT = 6343

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

while True:
                                                 
    data, addr = sock.recvfrom(3000) # 1386 bytes is the largest possible sFlow packet, by spec 3000 seems to be the number by practice
    sFlowData = sFlow(data)

    #Below this point is test code.

    print ""
    print "Source:", addr[0]
    #print "length:", sFlowData.len
    #print "DG Version:", sFlowData.dgVersion
    #print "Address Type:", sFlowData.addressType
    #print "Agent Address:", sFlowData.agentAddress
    #print "Sub Agent:", sFlowData.subAgent
    print "Sequence Number:", sFlowData.sequenceNumber
    #print "System UpTime:", sFlowData.sysUpTime
    #print "Number of Samples:", sFlowData.NumberSample
    #print ""
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
            #print "Record Sample Type:", sFlowData.sample[i].record[j].sampleType
            #print "Record Format:", sFlowData.sample[i].record[j].format
            #print "Record Length:", sFlowData.sample[i].record[j].len
            if sFlowData.sample[i].record[j].sampleType == 1:
                if sFlowData.sample[i].record[j].format == 1 and sFlowData.sample[i].record[j].enterprise == 0:
                    record = sFlowRawPacketHeader(sFlowData.sample[i].record[j].len, sFlowData.sample[i].record[j].data)
                    #print "Raw Packet Header Protocol:", record.headerProtocol
                    #print "Frame Length:", record.frameLength
                    #print "Payload Removed:", record.payloadRemoved
                    #print "Header Size:", record.headerSize

                elif sFlowData.sample[i].record[j].format == 2 and sFlowData.sample[i].record[j].enterprise == 0:
                    record = sFlowEthernetFrame(sFlowData.sample[i].record[j].len, sFlowData.sample[i].record[j].data)
                    #print "Ethernet Frame Length:", record.frameLength
                    #print "Ethernet Frame src MAC:", record.srcMAC
                    #print "Ethernet Frame dst MAC:", record.dstMAC
                    #print "Ethernet Frame Record Type:", record.type
                elif sFlowData.sample[i].record[j].format == 1001:
                    record = sFlowExtendedSwitch(sFlowData.sample[i].record[j].len, sFlowData.sample[i].record[j].data)
                    #print "Extended Switch:", record.srcVLAN
                    #print "Extended Switch:", record.srcPriority
                    #print "Extended Switch:", record.dstVLAN
                    #print "Extended Switch:", record.dstPriority
                    #print "Flow 1001"
                else:
                    print "Flow Record Enterprise:", sFlowData.sample[i].record[j].enterprise
                    print "Flow Record Type:", sFlowData.sample[i].record[j].format
            elif sFlowData.sample[i].record[j].sampleType == 2:
                if sFlowData.sample[i].record[j].format == 1:
                    record = sFlowIfCounter(sFlowData.sample[i].record[j].len, sFlowData.sample[i].record[j].data)
                    #print "If Counter Index:", record.index
                    #print "If Counter Type:", record.type
                    #print "If Counter Speed:", record.speed
                    #print "If Counter Direction:", record.direction
                    #print "If Counter Status:", record.status
                    #print "If Counter I Octets:", record.inputOctets
                    #print "If Counter I Packets:", record.inputPackets
                    #print "If Counter I Multicast:", record.inputMulticast
                    #print "If Counter I Broadcast:", record.inputBroadcast
                    #print "If Counter I Discards:", record.inputDiscarded
                    #print "If Counter I Errors:", record.inputErrors
                    #print "If Counter I Unknown:", record.inputUnknown 
                    #print "If Counter O Octets:", record.outputOctets
                    #print "If Counter O Packets:", record.outputPackets
                    #print "If Counter O Multicast:", record.outputMulticast
                    #print "If Counter O Broadcast:", record.outputBroadcast
                    #print "If Counter O Discard:", record.outputDiscarded
                    #print "If Counter O Errors:", record.outputErrors
                    #print "If Counter Promiscuous:", record.promiscuous
                    #print "Counter 1"
                elif sFlowData.sample[i].record[j].format == 2:
                    record = sFlowEthernetInterface(sFlowData.sample[i].record[j].len, sFlowData.sample[i].record[j].data)
                    #print "Ethernet Alignmet Error:", record.alignmentError
                    #print "Ethernet FCS Error:", record.fcsError
                    #print "Ethernet Single Collision Frames:", record.singleCollision
                    #print "Ethernet Multiple Collision Frames:", record.multipleCollision
                    #print "Ethernet SQE Test Error:", record.sqeTest
                    #print "Ethernet Deferred Transmissions:", record.deferred
                    #print "Ethernet Late Collisions:", record.lateCollision
                    #print "Ethernet Excessiove Collisions:", record.excessiveCollision
                    #print "Ethernet Internal Transmit Error:", record.internalTransmitError
                    #print "Ethernet Carrier Sense Error:", record.carrierSenseError
                    #print "Ethernet Frame Too Long:", record.frameTooLong
                    #print "Ethernet Internal Receive Error:", record.internalReceiveError
                    #print "Ethernet Symbol Error:", record.symbolError
                    #print "Counter 2"
                elif sFlowData.sample[i].record[j].format == 5:
                    record = sFlowVLAN(sFlowData.sample[i].record[j].len, sFlowData.sample[i].record[j].data)
                    #print "VLAN :", record.vlanID
                    #print "VLAN :", record.octets
                    #print "VLAN :", record.unicast
                    #print "VLAN :", record.multicast
                    #print "VLAN :", record.broadcast
                    #print "VLAN :", record.discard
                    #print "Counter 5"
                elif sFlowData.sample[i].record[j].format == 1001:
                    record = sFlowProcessor(sFlowData.sample[i].record[j].len, sFlowData.sample[i].record[j].data)
                    #print "Processor :", record.cpu5s 
                    #print "Processor :", record.cpu1m  
                    #print "Processor :", record.cpu5m
                    #print "Processor :", record.totalMemory 
                    #print "Processor :", record.freeMemory
                    #print "Counter 1001"
                elif sFlowData.sample[i].record[j].format == 2000:
                    record = sFlowHostDisc(sFlowData.sample[i].record[j].len, sFlowData.sample[i].record[j].data)
                    #print "Counter 2000"
                elif sFlowData.sample[i].record[j].format == 2001:
                    record = sFlowHostAdapters(sFlowData.sample[i].record[j].len, sFlowData.sample[i].record[j].data)
                    #print "Host Adpaters:", record.adapaters
                    #print "Counter 2001"
                elif sFlowData.sample[i].record[j].format == 2003:
                    record = sFlowHostCPU(sFlowData.sample[i].record[j].len, sFlowData.sample[i].record[j].data)
                    #print "Counter 2003"
                elif sFlowData.sample[i].record[j].format == 2004:
                    record = sFlowHostMemory(sFlowData.sample[i].record[j].len, sFlowData.sample[i].record[j].data)
                    #print "Host Memory Total:", record.memTotal
                    #print "Host Memory Free:", record.memFree
                    #print "Host Memory Shared:", record.memShared
                    #print "Host Memory Buffers:", record.memBuffers
                    #print "Host Memory Cache:", record.memCache
                    #print "Host Swap Memory Total:", record.swapTotal
                    #print "Host Swap Memory Free:", record.swapFree
                    #print "Host Page In:", record.pageIn
                    #print "Host Page Out:", record.pageOut
                    #print "Host Swap Page In:", record.swapIn
                    #print "Host Swap Page Out:", record.swapOut
                    #print "Counter 2004"
                elif sFlowData.sample[i].record[j].format == 2005:
                    record = sFlowHostDiskIO(sFlowData.sample[i].record[j].len, sFlowData.sample[i].record[j].data)
                    #print "Host disk:", record.diskTotal
                    #print "Host disk:", record.diskFree
                    #print "Host disk:", record.partMaxused
                    #print "Host disk:", record.read
                    #print "Host disk:", record.readByte
                    #print "Host disk:", record.readTime
                    #print "Host disk:", record.write
                    #print "Host disk:", record.writeByte
                    #print "Host disk:", record.writeTime
                    #print "Counter 2005"
                elif sFlowData.sample[i].record[j].format == 2006:
                    record = sFlowHostNetIO(sFlowData.sample[i].record[j].len, sFlowData.sample[i].record[j].data)
                elif sFlowData.sample[i].record[j].format == 2007:
                    record = sFlowMib2IP(sFlowData.sample[i].record[j].len, sFlowData.sample[i].record[j].data)
                elif sFlowData.sample[i].record[j].format == 2008:
                    record = sFlowMib2ICMP(sFlowData.sample[i].record[j].len, sFlowData.sample[i].record[j].data)
                elif sFlowData.sample[i].record[j].format == 2009:
                    record = sFlowMib2TCP(sFlowData.sample[i].record[j].len, sFlowData.sample[i].record[j].data)
                    #print "Counter 2009"
                    #print "TCP Algorithm:", record.algorithm
                    #print "TCP RTO Min:", record.rtoMin
                    #print "TCP RTO Max:", record.rtoMax
                    #print "TCP Max Connections:", record.maxConnection
                    #print "TCP Active Open:", record.activeOpen
                    #print "TCP Passive Open:", record.passiveOpen
                    #print "TCP Attempt Fail:", record.attemptFail
                    #print "TCP Established Reset:", record.establishedReset
                    #print "TCP Current Established:", record.currentEstablished
                    #print "TCP In Segments:", record.inSegment
                    #print "TCP Out Segments:", record.outSegment
                    #print "TCP Retransmit Segemnt:", record.retransmitSegment
                    #print "TCP In Error:", record.inError
                    #print "TCP Out Reset:", record.outReset
                    #print "TCP In C sum Error:", record.inCsumError
                elif sFlowData.sample[i].record[j].format == 2010:
                    record = sFlowMib2UDP(sFlowData.sample[i].record[j].len, sFlowData.sample[i].record[j].data)
                    #print "Counter 2010"
                    #print "UDP In Datagrams:", record.inDatagrams
                    #print "UDP No Ports:", record.noPorts
                    #print "UDP In Errors:", record.inErrors
                    #print "UDP Out Datagrams:", record.outDatagrams
                    #print "UDP Receive Buffer Error:", record.receiveBufferError
                    #print "UDP Send Buffer Error:", record.sendBufferError 
                    #print "UDP In Check Sum Error:", record.inCheckSumError 
                else:
                    print "Counter Record Enterprise:", sFlowData.sample[i].record[j].enterprise
                    print "Counter Record Type:", sFlowData.sample[i].record[j].format
                    




                
