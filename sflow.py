#!/usr/bin/python
from struct import unpack
from ipaddress import IPv4Address, IPv6Address
from binascii import hexlify
from uuid import UUID


# The sFlow Collector is a class for parsing sFlow data.

# sFlow datagrams contain a header, which may contain samples which may contain records.
#
# The datagram may not contain a sample, but if it does there will be at least on record.
#
# The records may have different formats.

#QUESTION (17-06-29) Is the raw data for each block actually needed? What is the cost for preserving them?


# sFlow
#   sample
#       record

#sFlow Record class.

class Record:
    def __init__(self, header, length, sampleType, dataGram):
        self.header = header
        self.enterprise = (self.header & 4294901760)/4096
        self.format = (self.header & 4095)
        self.len = length
        self.sampleType = sampleType
        self.data = dataGram

# sFlow Sample class.

class Sample:
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

            for _ in range(self.recordCount):
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

            for _ in range(self.recordCount):
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

class sFlow:
    def __init__(self, dataGram):
        
        dataPosition = 0
        self.sample = []
        self.data = dataGram
        self.dgVersion = struct.unpack('>i', dataGram[0:4])[0]
        self.addressType = struct.unpack('>i', dataGram[4:8])[0]
        self.len = len(dataGram)
        if self.addressType == 1:
            self.agentAddress = socket.inet_ntop(socket.AF_INET, dataGram[8:12])
            self.subAgent = struct.unpack('>i', dataGram[12:16])[0]
            self.sequenceNumber = struct.unpack('>i', dataGram[16:20])[0]
            self.sysUpTime = struct.unpack('>i', dataGram[20:24])[0]
            self.NumberSample = struct.unpack('>i', dataGram[24:28])[0]
            dataPosition = 28
        elif self.addressType == 2:
            self.agentAddress = socket.inet_ntop(socket.AF_INET6, dataGram[8:24])
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
            for _ in range(self.NumberSample):
                SampleHeader = dataGram[(dataPosition):(dataPosition + 4)]
                SampleSize = struct.unpack('>i', dataGram[(dataPosition + 4):(dataPosition + 8)])[0]
                SampleDataGram = dataGram[(dataPosition + 8):(dataPosition + SampleSize + 8)]

                self.sample.append(Sample(SampleHeader, SampleSize, SampleDataGram))
                dataPosition = dataPosition + 8 + SampleSize

# Flow
#   Raw Packet Header       1-0-1
#   Ethernet Frame          1-0-2
#   Extended Switch         1-0-1001

# Counter
#   Interface Counter       2-0-1
#   Ethernet Interface      2-0-2
#   VLAN                    2-0-5
#   Processor               2-0-1001
#   Port Name               2-0-1005
#   Host Description        2-0-2000
#   Host Adapaters          2-0-2001
#   Host Parent             2-0-2002
#   Host CPU                2-0-2003
#   Host Memory             2-0-2004
#   Host Disk IO            2-0-2005
#   Host Network IO         2-0-2006
#   MIB2 IP Group           2-0-2007
#   MIB2 ICMP Group         2-0-2008
#   MIB2 TCP Group          2-0-2009
#   MIB2 UDP Group          2-0-2010



#IDEA (17-03-07) Sanity check for the fixed length records could be implimented with a simple value check.

#Flow Record Types

class sFlowRawPacketHeader():
    "flowData: enterprise = 0, format = 1"

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.headerProtocol = unpack('>i', dataGram[0:4])[0]
        self.frameLength = unpack('>i', dataGram[4:8])[0]
        self.payloadRemoved = unpack('>i', dataGram[8:12])[0]
        self.headerSize = unpack('>i', dataGram[12:16])[0]
        self.header = dataGram[(16):(16 + self.headerSize)] 
        #Need a class for parsing the header information.


class sFlowEthernetFrame():
    "flowData: enterprise = 0, format = 2"

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.frameLength = unpack('>i', dataGram[0:4])[0]
        self.srcMAC = hexlify(dataGram[4:10])
        self.dstMAC = hexlify(dataGram[12:18])
        self.type = unpack('>i', dataGram[20:24])[0]


class sFlowSampledIpv4():
    "flowData: enterprise = 0, format = 3"

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.length = unpack('>i', dataGram[0:4])[0]
        self.protocol = unpack('>i', dataGram[4:8])[0]
        self.srcIp = IPv4Address(dataGram[8:12])
        self.dstIp = IPv4Address(dataGram[12:16])
        self.srcPort = unpack('>i', dataGram[16:20])[0]
        self.dstPort = unpack('>i', dataGram[20:24])[0]
        self.tcpFlags = unpack('>i', dataGram[24:28])[0]
        self.tos = unpack('>i', dataGram[28:32])[0]


class sFlowSampledIpv6():
    "flowData: enterprise = 0, format = 4"

    def __init__(self, length, dataGram):
        self.size = length
        self.data = dataGram
        self.length = unpack('>i', dataGram[0:4])[0]
        self.protocol = unpack('>i', dataGram[4:8])[0]
        self.srcIp = IPv6Address(dataGram[8:24])
        self.dstIp = IPv6Address(dataGram[24:40])
        self.srcPort = unpack('>i', dataGram[40:44])[0]
        self.dstPort = unpack('>i', dataGram[44:48])[0]
        self.tcpFlags = unpack('>i', dataGram[48:52])[0]
        self.priority = unpack('>i', dataGram[52:56])[0]


class sFlowExtendedSwitch():
    "flowData: enterprise = 0, format = 1001"

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.srcVLAN = unpack('>i', dataGram[0:4])[0]
        self.srcPriority = unpack('>i', dataGram[4:8])[0]
        self.dstVLAN = unpack('>i', dataGram[8:12])[0]
        self.dstPriority = unpack('>i', dataGram[12:16])[0]


class sFlowExtendedRouter():
    "flowData: enterprise = 0, format = 1002"

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.addressType = unpack('>i', dataGram[0:4])[0]
        if self.addressType == 1:
            self.nextHop = IPv4Address(dataGram[4:8])
            dataPosition = 8
        elif self.addressType == 2:
            self.nextHop = IPv6Address(dataGram[4:20])
            dataPosition = 20
        else:
            self.nextHop = 0
            self.srcMaskLen = 0
            self.dstMaskLen = 0
            return
        self.srcMaskLen = unpack('>i', dataGram[dataPosition:(dataPosition + 4)])[0]
        dataPosition += 4
        self.dstMaskLen = unpack('>i', dataGram[dataPosition:(dataPosition + 4)])[0]
        


class sFlowExtendedGateway():
    "flowData: enterprise = 0, format = 1003"

    def __init__(self, length, dataGram):
        self.size = length
        self.data = dataGram
        self.addressType = unpack('>i', dataGram[0:4])[0]
        if self.addressType == 1:
            self.nextHop = IPv4Address(dataGram[4:8])
            dataPosition = 8
        elif self.addressType == 2:
            self.nextHop = IPv6Address(dataGram[4:20])
            dataPosition = 20
        else:
            self.nextHop = 0
            self.asNumber = 0
            self.srcAutonomousSystemsNumber = 0
            self.srcPeerAutonomousSystemsNumber = 0
            self.asPathType = 0
            self.asPathCount = 0
            self.dstAutonomousSystemsPath = []
            communitiesCount = 0
            self.communities = []
            self.localpref = 0
            return
        self.asNumber = unpack('>i', dataGram[dataPosition:(dataPosition + 4)])[0]
        dataPosition += 4
        self.srcAsNumber = unpack('>i', dataGram[dataPosition:(dataPosition + 4)])[0]
        dataPosition += 4
        self.srcPeerAsNumber = unpack('>i', dataGram[dataPosition:(dataPosition + 4)])[0]
        dataPosition += 4
        self.asPathType = unpack('>i', dataGram[dataPosition:(dataPosition + 4)])[0]
        dataPosition += 4
        self.asPathCount = unpack('>i', dataGram[dataPosition:(dataPosition + 4)])[0]
        dataPosition += 4
        self.dstAsPath = unpack(
            f'>{"i" * self.asPathCount}', 
            dataGram[dataPosition:(dataPosition + self.asPathCount * 4)])
        dataPosition += self.asPathCount * 4
        self.communitiesCount = unpack('>i', dataGram[dataPosition:(dataPosition + 4)])[0]
        dataPosition += 4
        self.communities = unpack(
            f'>{"i" * communitiesCount}', 
            dataGram[dataPosition:(dataPosition + communitiesCount * 4)])
        dataPosition += communitiesCount * 4
        self.localpref = unpack('>i', dataGram[dataPosition:(dataPosition + 4)])[0]


class sFlowExtendedUser():
    "flowData: enterprise = 0, format = 1004"

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.srcCharset = unpack('>i', dataGram[0:4])
        nameLength = unpack('>i', dataGram[4:8])[0]
        self.srcUser = dataGram[8:(8 + nameLength)].decode("utf-8")
        dataPosition = nameLength + (4 - nameLength) % 4
        self.dstCharset = dataGram[dataPosition:(dataPosition + nameLength)].decode('utf-8')
        dataPosition += 4
        nameLength = unpack('>i', dataGram[4:8])[0]
        self.dstUser = dataGram[dataPosition:(dataPosition + nameLength)].decode("utf-8")


class sFlowExtendedUrl():
    "flowData: enterprise = 0, format = 1005"

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.direction = unpack('>i', dataGram[0:4])[0]
        nameLength = min(unpack('>i', dataGram[4:8])[0], 255)
        dataPosition = 8
        self.url = dataGram[dataPosition:(dataPosition + nameLength)].decode('utf-8')
        dataPosition += nameLength + (4 - nameLength) % 4
        nameLength = min(unpack('>i', dataGram[dataPosition:(dataPosition + 4)])[0], 255)
        dataPosition += 4
        self.host = dataGram[dataPosition:(dataPosition + nameLength)].decode('utf-8')
        nameLength = unpack('>i', dataGram[0:4])[0]
        self.PortName = dataGram[dataPosition:(dataPosition + nameLength)].decode("utf-8")


class sFlowExtendedMpls():
    "flowData: enterprise = 0, format = 1006"

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.addressType = unpack('>i', dataGram[0:4])[0]
        dataPosition = 4
        if self.addressType == 1:
            self.nextHop = IPv4Address(dataGram[dataPosition:(dataPosition + 4)])
            dataPosition += 4
        elif self.addressType == 2:
            self.nextHop = IPv6Address(dataGram[dataPosition:(dataPosition + 16)])
            dataPosition += 16
        else:
            self.nextHop = 0
            self.inLabelStackCount = 0
            self.inLabelStack = []
            self.outLabelStackCount = 0
            self.outLabelStack = []
            return
        self.inLabelStackCount = unpack('>i', dataGram[dataPosition:(dataPosition + 4)])[0]
        dataPosition += 4
        self.inLabelStack = unpack(
            f'>{"i" * self.inLabelStackCount}', 
            dataGram[dataPosition:(dataPosition + self.inLabelStackCount * 4)])
        dataPosition += self.inLabelStackCount * 4
        self.outLabelStackCount = unpack('>i', dataGram[dataPosition:(dataPosition + 4)])[0]
        dataPosition += 4
        self.outLabelStack = unpack(
            f'>{"i" * self.outLabelStackCount}', 
            dataGram[dataPosition:(dataPosition + self.outLabelStackCount * 4)])


class sFlowExtendedNat():
    "flowData: enterprise = 0, format = 1007"

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.srcAddressType = unpack('>i', dataGram[0:4])[0]
        dataPosition = 4
        if self.srcAddressType == 1:
            self.srcAddress = IPv4Address(dataGram[dataPosition:(dataPosition + 4)])
            dataPosition += 4
        elif self.srcAddressType == 2:
            self.srcAddress = IPv6Address(dataGram[dataPosition:(dataPosition + 16)])
            dataPosition += 16
        else:
            self.srcAddress = 0
            self.dstAddress = 0
            return
        self.dstAddressType = unpack('>i', dataGram[0:4])[0]
        dataPosition += 4
        if self.dstAddressType == 1:
            self.dstAddress = IPv4Address(dataGram[dataPosition:(dataPosition + 4)])
            dataPosition += 4
        elif self.dstAddressType == 2:
            self.dstAddress = IPv6Address(dataGram[dataPosition:(dataPosition + 16)])
            dataPosition += 16
        else:
            self.dstAddress = 0
            return


class sFlowExtendedMplsTunnel():
    "flowData: enterprise = 0, format = 1008"

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        nameLength = min(unpack('>i', dataGram[0:4])[0], 255)
        self.host = dataGram[4:(4 + nameLength)].decode('utf-8')
        dataPosition = 4 + nameLength + (4 - nameLength) % 4
        self.tunnelId = unpack('>i', dataGram[dataPosition:(dataPosition + 4)])[0]
        dataPosition += 4
        self.tunnelCos = unpack('>i', dataGram[dataPosition:(dataPosition + 4)])[0]


class sFlowExtendedMplsVc():
    "flowData: enterprise = 0, format = 1009"

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        nameLength = min(unpack('>i', dataGram[0:4])[0], 255)
        self.vcInstanceName = dataGram[4:(4 + nameLength)].decode('utf-8')
        dataPosition = 4 + nameLength + (4 - nameLength) % 4
        self.vllVcId = unpack('>i', dataGram[dataPosition:(dataPosition + 4)])[0]
        dataPosition += 4
        self.vcLabelCos = unpack('>i', dataGram[dataPosition:(dataPosition + 4)])[0]


class sFlowExtendedMpls_FTN():
    "flowData: enterprise = 0, format = 1010"

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        nameLength = min(unpack('>i', dataGram[0:4])[0], 255)
        self.mplsFTNDescr = dataGram[4:(4 + nameLength)].decode('utf-8')
        dataPosition = 4 + nameLength + (4 - nameLength) % 4
        self.mplsFTNMask = unpack('>i', dataGram[dataPosition:(dataPosition + 4)])[0]


class sFlowExtendedMpls_LDP_FEC():
    "flowData: enterprise = 0, format = 1011"

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.mplsFecAddrPrefixLength = unpack('>i', dataGram)[0]


class sFlowExtendedVlantunnel():
    "flowData: enterprise = 0, format = 1012"

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        stackCount = unpack('>i', dataGram[0:4])[0]
        self.stack = unpack(f'>{"i" * stackCount}', dataGram[4:(4 + stackCount * 4)])


class sFlowExtendedSocketIpv4():
    "flowData: enterprise = 0, format = 2100"

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.protocol = unpack('>i', dataGram[0:4])[0]
        self.localIp = IPv4Address(dataGram[4:8])
        self.remoteIp = IPv4Address(dataGram[8:12])
        self.localPort = unpack('>i', dataGram[12:16])[0]
        self.remotePort = unpack('>i', dataGram[16:20])[0]


class sFlowExtendedSocketIpv6():
    "flowData: enterprise = 0, format = 2101"

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.protocol = unpack('>i', dataGram[0:4])[0]
        self.localIp = IPv6Address(dataGram[4:20])
        self.remoteIp = IPv6Address(dataGram[20:36])
        self.localPort = unpack('>i', dataGram[36:40])[0]
        self.remotePort = unpack('>i', dataGram[40:44])[0]


#Counter Record Types

class sFlowIfCounter:
    "counterData: enterprise = 0, format = 1"

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.index = unpack('>i', dataGram[0:4])[0]
        self.type = unpack('>i', dataGram[4:8])[0]
        self.speed = unpack('>q', dataGram[8:16])[0] #64-bit
        self.direction = unpack('>i', dataGram[16:20])[0]
        self.status = unpack('>i', dataGram[20:24])[0] #This is really a 2-bit value
        self.inputOctets = unpack('>q', dataGram[24:32])[0] #64-bit
        self.inputPackets = unpack('>i', dataGram[32:36])[0]
        self.inputMulticast = unpack('>i', dataGram[36:40])[0]
        self.inputBroadcast = unpack('>i', dataGram[40:44])[0]
        self.inputDiscarded = unpack('>i', dataGram[44:48])[0]
        self.inputErrors = unpack('>i', dataGram[48:52])[0]
        self.inputUnknown = unpack('>i', dataGram[52:56])[0]
        self.outputOctets = unpack('>q', dataGram[56:64])[0] #64-bit
        self.outputPackets = unpack('>i', dataGram[64:68])[0]
        self.outputMulticast = unpack('>i', dataGram[68:72])[0]
        self.outputBroadcast = unpack('>i', dataGram[72:76])[0]
        self.outputDiscarded = unpack('>i', dataGram[76:80])[0]
        self.outputErrors = unpack('>i', dataGram[80:84])[0]
        self.promiscuous = unpack('>i', dataGram[84:88])[0]


class sFlowEthernetInterface: #2-2 (52 bytes)
    "counterData: enterprise = 0, format = 2"

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.alignmentError = unpack('>i', dataGram[0:4])[0]
        self.fcsError = unpack('>i', dataGram[4:8])[0]
        self.singleCollision = unpack('>i', dataGram[8:12])[0]
        self.multipleCollision = unpack('>i', dataGram[12:16])[0]
        self.sqeTest = unpack('>i', dataGram[16:20])[0]
        self.deferred = unpack('>i', dataGram[20:24])[0]
        self.lateCollision = unpack('>i', dataGram[24:28])[0]
        self.excessiveCollision = unpack('>i', dataGram[28:32])[0]
        self.internalTransmitError = unpack('>i', dataGram[32:36])[0]
        self.carrierSenseError = unpack('>i', dataGram[36:40])[0]
        self.frameTooLong = unpack('>i', dataGram[40:44])[0]
        self.internalReceiveError = unpack('>i', dataGram[44:48])[0]
        self.symbolError = unpack('>i', dataGram[48:52])[0]


class sFlowTokenringCounters():
    "counterData: enterprise = 0, format = 3"

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.dot5StatsLineErrors = unpack('>i', dataGram[0:4])[0]
        self.dot5StatsBurstErrors = unpack('>i', dataGram[4:8])[0]
        self.dot5StatsACErrors = unpack('>i', dataGram[8:12])[0]
        self.dot5StatsAbortTransErrors = unpack('>i', dataGram[12:16])[0]
        self.dot5StatsInternalErrors = unpack('>i', dataGram[16:20])[0]
        self.dot5StatsLostFrameErrors = unpack('>i', dataGram[20:24])[0]
        self.dot5StatsReceiveCongestions = unpack('>i', dataGram[24:28])[0]
        self.dot5StatsFrameCopiedErrors = unpack('>i', dataGram[28:32])[0]
        self.dot5StatsTokenErrors = unpack('>i', dataGram[32:36])[0]
        self.dot5StatsSoftErrors = unpack('>i', dataGram[36:40])[0]
        self.dot5StatsHardErrors = unpack('>i', dataGram[40:44])[0]
        self.dot5StatsSignalLoss = unpack('>i', dataGram[44:48])[0]
        self.dot5StatsTransmitBeacons = unpack('>i', dataGram[48:52])[0]
        self.dot5StatsRecoverys = unpack('>i', dataGram[52:56])[0]
        self.dot5StatsLobeWires = unpack('>i', dataGram[56:60])[0]
        self.dot5StatsRemoves = unpack('>i', dataGram[60:64])[0]
        self.dot5StatsSingles = unpack('>i', dataGram[64:68])[0]
        self.dot5StatsFreqErrors = unpack('>i', dataGram[68:72])[0]


class sFlowVgCounters():
    "counterData: enterprise = 0, format = 4"

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.dot12InHighPriorityFrames = unpack('>i', dataGram[0:4])[0]
        self.dot12InHighPriorityOctets = unpack('>q', dataGram[4:12])[0]
        self.dot12InNormPriorityFrames = unpack('>i', dataGram[12:16])[0]
        self.dot12InNormPriorityOctets = unpack('>q', dataGram[16:24])[0]
        self.dot12InIPMErrors = unpack('>i', dataGram[24:28])[0]
        self.dot12InOversizeFrameErrors = unpack('>i', dataGram[28:32])[0]
        self.dot12InDataErrors = unpack('>i', dataGram[32:36])[0]
        self.dot12InNullAddressedFrames = unpack('>i', dataGram[36:40])[0]
        self.dot12OutHighPriorityFrames = unpack('>i', dataGram[40:44])[0]
        self.dot12OutHighPriorityOctets = unpack('>q', dataGram[44:52])[0]
        self.dot12TransitionIntoTrainings = unpack('>i', dataGram[52:56])[0]
        self.dot12HCInHighPriorityOctets = unpack('>q', dataGram[56:64])[0]
        self.dot12HCInNormPriorityOctets = unpack('>q', dataGram[64:72])[0]
        self.dot12HCOutHighPriorityOctets = unpack('>q', dataGram[72:80])[0]


class sFlowVLAN: #2-5 (28 bytes)
    "counterData: enterprise = 0, format = 5"

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.vlanID = unpack('>i', dataGram[0:4])[0]
        self.octets = unpack('>q', dataGram[4:12])[0] #64-bit
        self.unicast = unpack('>i', dataGram[12:16])[0]
        self.multicast = unpack('>i', dataGram[16:20])[0]
        self.broadcast = unpack('>i', dataGram[20:24])[0]
        self.discard = unpack('>i', dataGram[24:28])[0]


class sFlowProcessor():
    "counterData: enterprise = 0, format = 1001"

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.cpu5s = unpack('>i', dataGram[0:4])[0]
        self.cpu1m = unpack('>i', dataGram[4:8])[0] 
        self.cpu5m = unpack('>i', dataGram[8:12])[0]
        self.totalMemory = unpack('>q', dataGram[12:20])[0] #64-bit
        self.freeMemory = unpack('>q', dataGram[20:28])[0] #64-bit       


class sFlowOfPort():
    "counterData: enterprise = 0, format = 1004"

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.datapathId = unpack('>i', dataGram[0:8])[0]
        self.portNo = unpack('>i', dataGram[8:12])[0]


class sFlowPortName():
    "counterData: enterprise = 0, format = 1005"

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        nameLength = unpack('>i', dataGram[0:4])[0]
        self.PortName = dataGram[4:(4 + nameLength)].decode('utf-8')


class sFlowHostDescr():
    "counterData: enterprise = 0, format = 2000"

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        nameLength = min(unpack('>i', dataGram[0:4])[0], 64)
        dataPosition = 4
        self.hostname = dataGram[dataPosition:(dataPosition + nameLength)].decode('utf-8')
        dataPosition += nameLength + (4 - nameLength) % 4
        self.uuid = UUID(bytes=dataGram[dataPosition:(dataPosition + 16)])
        dataPosition = dataPosition + 16
        self.machineType = unpack('>i', dataGram[dataPosition:(dataPosition + 4)])[0]
        dataPosition = dataPosition + 4
        self.osName = unpack('>i', dataGram[dataPosition:(dataPosition + 4)])[0]
        dataPosition = dataPosition + 4
        nameLength = min(unpack('>i', dataGram[dataPosition:(dataPosition + 4)])[0], 32)
        dataPosition += 4
        self.osRelease = dataGram[dataPosition:(dataPosition + nameLength)].decode('utf-8')


class sFlowHostAdapters():
    "counterData: enterprise = 0, format = 2001"

    class hostAdapter():
        def __init__(self):
            self.ifIndex = None
            self.macAddressCount = None
            self.macAddresses = None

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.adapters = []
        hostAdapterCount = unpack('>i', dataGram[0:4])[0]
        dataPosition = 4
        for _ in range(hostAdapterCount):
            hostadapter = self.hostAdapter()
            hostadapter.ifIndex = unpack(
                '>i', dataGram[dataPosition:(dataPosition + 4)])[0]
            dataPosition += 4
            hostadapter.macAddressCount = unpack(
                '>i', dataGram[dataPosition:(dataPosition + 4)])[0]
            dataPosition += 4
            hostadapter.macAddresses = []
            for macNum in range(hostadapter.macAddressCount):
                hostadapter.macAddresses.append(
                    hexlify(
                        dataGram[(dataPosition + macNum * 8):(dataPosition + macNum * 8 + 6)]))
            dataPosition += hostadapter.macAddressCount * 8
            self.adapters.append(hostadapter)


class sFlowHostParent:
    "counterData: enterprise = 0, format = 2002"

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.containerType = unpack('>i', dataGram[0:4])[0]
        self.containerIndex = unpack('>i', dataGram[4:8])[0]


class sFlowHostCPU:
    "counterData: enterprise = 0, format = 2003"

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.avgLoad1 = unpack('>f', dataGram[0:4])[0] #Floating Point
        self.avgLoad5 = unpack('>f', dataGram[4:8])[0] #Floating Point
        self.avgLoad15 = unpack('>f', dataGram[8:12])[0] #Floating Point
        self.runProcess = unpack('>i', dataGram[12:16])[0]
        self.totalProcess = unpack('>i', dataGram[16:20])[0]
        self.numCPU = unpack('>i', dataGram[20:24])[0]
        self.mhz = unpack('>i', dataGram[24:28])[0]
        self.uptime = unpack('>i', dataGram[28:32])[0]
        self.timeUser = unpack('>i', dataGram[32:36])[0]
        self.timeNices = unpack('>i', dataGram[36:40])[0]
        self.timeKennal = unpack('>i', dataGram[40:44])[0]
        self.timeIdle = unpack('>i', dataGram[44:48])[0]
        self.timeIO = unpack('>i', dataGram[48:52])[0]
        self.timeInterrupt = unpack('>i', dataGram[52:56])[0]
        self.timeSoftInterrupt = unpack('>i', dataGram[56:60])[0]
        self.interrupt = unpack('>i', dataGram[60:64])[0]
        self.contextSwitch = unpack('>i', dataGram[64:68])[0]
        self.virtualInstance = unpack('>i', dataGram[68:72])[0]
        self.guestOS = unpack('>i', dataGram[72:76])[0]
        self.guestNice = unpack('>i', dataGram[76:80])[0]

class sFlowHostMemory:
    "counterData: enterprise = 0, format = 2004"

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.memTotal = unpack('>q', dataGram[0:8])[0] #64-bit
        self.memFree = unpack('>q', dataGram[8:16])[0] #64-bit
        self.memShared = unpack('>q', dataGram[16:24])[0] #64-bit
        self.memBuffers = unpack('>q', dataGram[24:32])[0] #64-bit
        self.memCache = unpack('>q', dataGram[32:40])[0] #64-bit
        self.swapTotal = unpack('>q', dataGram[40:48])[0] #64-bit
        self.swapFree = unpack('>q', dataGram[48:56])[0] #64-bit
        self.pageIn = unpack('>i', dataGram[56:60])[0]
        self.pageOut = unpack('>i', dataGram[60:64])[0]
        self.swapIn = unpack('>i', dataGram[64:68])[0]
        self.swapOut = unpack('>i', dataGram[68:72])[0]

class sFlowHostDiskIO:
    "counterData: enterprise = 0, format = 2005"

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.diskTotal = unpack('>q', dataGram[0:8])[0] #64-bit
        self.diskFree = unpack('>q', dataGram[8:16])[0] #64-bit
        self.partMaxused = (unpack('>i', dataGram[16:20])[0])/ float(100)
        self.read = unpack('>i', dataGram[20:24])[0]
        self.readByte = unpack('>q', dataGram[24:32])[0] #64-bit
        self.readTime = unpack('>i', dataGram[32:36])[0]
        self.write = unpack('>i', dataGram[36:40])[0]
        self.writeByte = unpack('>q', dataGram[40:48])[0] #64-bit
        self.writeTime = unpack('>i', dataGram[48:52])[0]

class sFlowHostNetIO:
    "counterData: enterprise = 0, format = 2006"

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.inByte = unpack('>q', dataGram[0:8])[0] #64-bit
        self.inPacket = unpack('>i', dataGram[8:12])[0]
        self.inError = unpack('>i', dataGram[12:16])[0]
        self.inDrop = unpack('>i', dataGram[16:20])[0]
        self.outByte = unpack('>q', dataGram[20:28])[0] #64-bit
        self.outPacket = unpack('>i', dataGram[28:32])[0]
        self.outError = unpack('>i', dataGram[32:36])[0]
        self.outDrop = unpack('>i', dataGram[36:40])[0]

class sFlowMib2IP:
    "counterData: enterprise = 0, format = 2007"

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.forwarding = unpack('>i', dataGram[0:4])[0]
        self.defaultTTL = unpack('>i', dataGram[4:8])[0]
        self.inReceives = unpack('>i', dataGram[8:12])[0]
        self.inHeaderErrors = unpack('>i', dataGram[12:16])[0]
        self.inAddressErrors = unpack('>i', dataGram[16:20])[0]
        self.inForwardDatagrams = unpack('>i', dataGram[20:24])[0]
        self.inUnknownProtocols = unpack('>i', dataGram[24:28])[0]
        self.inDiscards = unpack('>i', dataGram[28:32])[0]
        self.inDelivers = unpack('>i', dataGram[32:36])[0]
        self.outRequests = unpack('>i', dataGram[36:40])[0]
        self.outDiscards = unpack('>i', dataGram[40:44])[0]
        self.outNoRoutes = unpack('>i', dataGram[44:48])[0]
        self.reassemblyTimeout = unpack('>i', dataGram[48:52])[0]
        self.reassemblyRequired = unpack('>i', dataGram[52:56])[0]
        self.reassemblyOkay = unpack('>i', dataGram[56:60])[0]
        self.reassemblyFail = unpack('>i', dataGram[60:64])[0]
        self.fragmentOkay = unpack('>i', dataGram[64:68])[0]
        self.fragmentFail = unpack('>i', dataGram[68:72])[0]
        self.fragmentCreate = unpack('>i', dataGram[72:76])[0]

class sFlowMib2ICMP:
    "counterData: enterprise = 0, format = 2008"

    def __init__(self, length, dataGram):
        self.len = length 
        self.data = dataGram
        self.inMessage = unpack('>i', dataGram[0:4])[0]
        self.inError = unpack('>i', dataGram[4:8])[0]
        self.inDestinationUnreachable = unpack('>i', dataGram[8:12])[0]
        self.inTimeExceeded = unpack('>i', dataGram[12:16])[0]
        self.inParameterProblem = unpack('>i', dataGram[16:20])[0]
        self.inSourceQuence = unpack('>i', dataGram[20:24])[0]
        self.inRedirect = unpack('>i', dataGram[24:28])[0]
        self.inEcho = unpack('>i', dataGram[28:32])[0]
        self.inEchoReply = unpack('>i', dataGram[32:36])[0]
        self.inTimestamp = unpack('>i', dataGram[36:40])[0]
        self.inAddressMask = unpack('>i', dataGram[40:44])[0]
        self.inAddressMaskReply = unpack('>i', dataGram[44:48])[0]
        self.outMessage = unpack('>i', dataGram[48:52])[0]
        self.outError = unpack('>i', dataGram[52:56])[0]
        self.outDestinationUnreachable = unpack('>i', dataGram[56:60])[0]
        self.outTimeExceeded = unpack('>i', dataGram[60:64])[0]
        self.outParameterProblem = unpack('>i', dataGram[64:68])[0]
        self.outSourceQuence = unpack('>i', dataGram[68:72])[0]
        self.outRedirect = unpack('>i', dataGram[72:76])[0]
        self.outEcho = unpack('>i', dataGram[76:80])[0]
        self.outEchoReply = unpack('>i', dataGram[80:84])[0]
        self.outTimestamp = unpack('>i', dataGram[84:88])[0]
        self.outTimestampReply = unpack('>i', dataGram[88:92])[0]
        self.outAddressMask = unpack('>i', dataGram[92:96])[0]
        self.outAddressMaskReplay = unpack('>i', dataGram[96:100])[0]

class sFlowMib2TCP:
    "counterData: enterprise = 0, format = 2009"

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.algorithm = unpack('>i', dataGram[0:4])[0]
        self.rtoMin = unpack('>i', dataGram[4:8])[0]
        self.rtoMax = unpack('>i', dataGram[8:12])[0]
        self.maxConnection = unpack('>i', dataGram[12:16])[0]
        self.activeOpen = unpack('>i', dataGram[16:20])[0]
        self.passiveOpen = unpack('>i', dataGram[20:24])[0]
        self.attemptFail = unpack('>i', dataGram[24:28])[0]
        self.establishedReset = unpack('>i', dataGram[28:32])[0]
        self.currentEstablished = unpack('>i', dataGram[32:36])[0]
        self.inSegment = unpack('>i', dataGram[36:40])[0]
        self.outSegment = unpack('>i', dataGram[40:44])[0]
        self.retransmitSegment = unpack('>i', dataGram[44:48])[0]
        self.inError = unpack('>i', dataGram[48:52])[0]
        self.outReset = unpack('>i', dataGram[52:56])[0]
        self.inCsumError = unpack('>i', dataGram[56:60])[0]

class sFlowMib2UDP:
    "counterData: enterprise = 0, format = 2010"

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.inDatagrams = unpack('>i', dataGram[0:4])[0]
        self.noPorts = unpack('>i', dataGram[4:8])[0]
        self.inErrors = unpack('>i', dataGram[8:12])[0]
        self.outDatagrams = unpack('>i', dataGram[12:16])[0]
        self.receiveBufferError = unpack('>i', dataGram[16:20])[0]
        self.sendBufferError = unpack('>i', dataGram[20:24])[0]
        self.inCheckSumError = unpack('>i', dataGram[24:28])[0]


class virtNode():
    "counterData: enterprise = 0, format = 2100"

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.mhz = unpack('>i', dataGram[0:4])[0]
        self.cpus = unpack('>i', dataGram[4:8])[0]
        self.memory = unpack('>q', dataGram[8:16])[0]
        self.memoryFree = unpack('>q', dataGram[16:24])[0]
        self.numDomains = unpack('>i', dataGram[24:28])[0]


class virtCpu():
    "counterData: enterprise = 0, format = 2101"

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.state = unpack('>i', dataGram[0:4])[0]
        self.cpuTime = unpack('>i', dataGram[4:8])[0]
        self.nrVirtCpu = unpack('>i', dataGram[8:12])[0]


class virtMemory():
    "counterData: enterprise = 0, format = 2102"

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.memory = unpack('>q', dataGram[0:8])[0]
        self.maxMemory = unpack('>q', dataGram[8:16])[0]


class virtDiskIo():
    "counterData: enterprise = 0, format = 2103"

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.capacity = unpack('>q', dataGram[0:8])[0]
        self.allocation = unpack('>q', dataGram[8:16])[0]
        self.available = unpack('>q', dataGram[16:24])[0]
        self.rdReq = unpack('>i', dataGram[24:28])[0]
        self.rdBytes = unpack('>q', dataGram[28:36])[0]
        self.wrReq = unpack('>i', dataGram[36:40])[0]
        self.wrBytes = unpack('>q', dataGram[40:48])[0]
        self.errs = unpack('>i', dataGram[48:52])[0]


class virtNetIo():
    "counterData: enterprise = 0, format = 2104"

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.rxBytes = unpack('>q', dataGram[0:8])[0]
        self.rxPackets = unpack('>i', dataGram[8:12])[0]
        self.rxErrs = unpack('>i', dataGram[12:16])[0]
        self.rxDrop = unpack('>i', dataGram[16:20])[0]
        self.txBytes = unpack('>q', dataGram[20:28])[0]
        self.txPackets = unpack('>i', dataGram[28:32])[0]
        self.txErrs = unpack('>i', dataGram[32:36])[0]
        self.txDrop = unpack('>i', dataGram[36:40])[0]
