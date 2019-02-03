from struct import unpack

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
        self.header = dataGram[(16):(16 + self.headerSize)] #Need a class for parsing the header information.


class sFlowEthernetFrame():
    "flowData: enterprise = 0, format = 2"

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.frameLength = unpack('>i', dataGram[0:4])[0]
        self.srcMAC = binascii.hexlify(dataGram[4:10])
        self.dstMAC = binascii.hexlify(dataGram[12:18])
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
        self.dstAsPath = unpack(f'>{"i" * self.asPathCount}', dataGram[dataPosition:(dataPosition + self.asPathCount * 4)])
        dataPosition += self.asPathCount * 4
        self.communitiesCount = unpack('>i', dataGram[dataPosition:(dataPosition + 4)])[0]
        dataPosition += 4
        self.communities = unpack(f'>{"i" * communitiesCount}', dataGram[dataPosition:(dataPosition + communitiesCount * 4)])
        dataPosition += communitiesCount * 4
        self.localpref = unpack('>i', dataGram[dataPosition:(dataPosition + 4)])[0]


class sFlowExtendedUser():
    "flowData: enterprise = 0, format = 1004"

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.srcCharset = unpack('>i', dataGram[0:4])
        nameLength = struct.unpack('>i', dataGram[4:8])[0]
        self.srcUser = dataGram[8:(8 + nameLength)].decode("utf-8")
        dataPostion = nameLength + (4 - nameLength) % 4
        self.dstCharset = dataGram[dataPosition:(dataPosition + nameLength)].decode('utf-8')
        dataPostion += 4
        nameLength = struct.unpack('>i', dataGram[4:8])[0]
        self.dstUser = dataGram[dataPosition:(dataPosition + nameLength)].decode("utf-8")


class sFlowExtendedUrl():
    "flowData: enterprise = 0, format = 1005"

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.direction = unpack('>i', dataGram[0:4])[0]
        dataPosition = 4
        nameLength = min(unpack('>i', dataGram[dataPosition:(dataPosition + 4)])[0], 255)
        dataPostion += 4
        self.url = dataGram[dataPosition:(dataPosition + nameLength)].decode('utf-8')
        dataPostion += nameLength + (4 - nameLength) % 4
        nameLength = min(unpack('>i', dataGram[dataPosition:(dataPosition + 4)])[0], 255)
        dataPostion += 4
        self.host = dataGram[dataPosition:(dataPosition + nameLength)].decode('utf-8')
        nameLength = struct.unpack('>i', dataGram[0:4])[0]
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
            self.inLabelStackCount
            self.inLabelStack = []
            self.outLabelStackCount = 0
            self.outLabelStack = []
            return
        self.inLabelStackCount = unpack('>i', dataGram[dataPosition:(dataPosition + 4)])[0]
        dataPosition += 4
        self.inLabelStack = unpack(f'>{"i" * self.inLabelStackCount}', dataGram[dataPosition:(dataPosition + self.inLabelStackCount * 4)])
        dataPosition += self.inLabelStackCount * 4
        self.outLabelStackCount = unpack('>i', dataGram[dataPosition:(dataPosition + 4)])[0]
        dataPosition += 4
        self.outLabelStack = unpack(f'>{"i" * self.outLabelStackCount}', dataGram[dataPosition:(dataPosition + self.outLabelStackCount * 4)])


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
        dataPostion = 4 + nameLength + (4 - nameLength) % 4
        self.tunnelId = unpack('>i', dataGram[dataPosition:(dataPosition + 4)])[0]
        dataPostion += 4
        self.tunnelCos = unpack('>i', dataGram[dataPosition:(dataPosition + 4)])[0]


class sFlowExtendedMplsVc():
    "flowData: enterprise = 0, format = 1009"

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        nameLength = min(unpack('>i', dataGram[0:4])[0], 255)
        self.vcInstanceName = dataGram[4:(4 + nameLength)].decode('utf-8')
        dataPostion += 4 + nameLength + (4 - nameLength) % 4
        self.vllVcId = unpack('>i', dataGram[dataPosition:(dataPosition + 4)])[0]
        dataPostion += 4
        self.vcLabelCos = unpack('>i', dataGram[dataPosition:(dataPosition + 4)])[0]


class sFlowExtendedMpls_FTN():
    "flowData: enterprise = 0, format = 1010"

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        nameLength = min(unpack('>i', dataGram[0:4])[0], 255)
        self.mplsFTNDescr = dataGram[4:(4 + nameLength)].decode('utf-8')
        dataPostion += 4 + nameLength + (4 - nameLength) % 4
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
        self.stackCount = unpack('>i', dataGram[0:4])[0]
        self.stack = unpack(f'>{i * stackCount}', dataGram[4:(4 + stackCount * 4)])


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
    "counterData: enterprise = 0, format = 2"

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


class sFlowTokenringCounters():
    "counterData: enterprise = 0, format = 3"

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.dot5StatsLineErrors = struct.unpack('>i', dataGram[0:4])[0]
        self.dot5StatsBurstErrors = struct.unpack('>i', dataGram[4:8])[0]
        self.dot5StatsACErrors = struct.unpack('>i', dataGram[8:12])[0]
        self.dot5StatsAbortTransErrors = struct.unpack('>i', dataGram[12:16])[0]
        self.dot5StatsInternalErrors = struct.unpack('>i', dataGram[16:20])[0]
        self.dot5StatsLostFrameErrors = struct.unpack('>i', dataGram[20:24])[0]
        self.dot5StatsReceiveCongestions = struct.unpack('>i', dataGram[24:28])[0]
        self.dot5StatsFrameCopiedErrors = struct.unpack('>i', dataGram[28:32])[0]
        self.dot5StatsTokenErrors = struct.unpack('>i', dataGram[32:36])[0]
        self.dot5StatsSoftErrors = struct.unpack('>i', dataGram[36:40])[0]
        self.dot5StatsHardErrors = struct.unpack('>i', dataGram[40:44])[0]
        self.dot5StatsSignalLoss = struct.unpack('>i', dataGram[44:48])[0]
        self.dot5StatsTransmitBeacons = struct.unpack('>i', dataGram[48:52])[0]
        self.dot5StatsRecoverys = struct.unpack('>i', dataGram[52:56])[0]
        self.dot5StatsLobeWires = struct.unpack('>i', dataGram[56:60])[0]
        self.dot5StatsRemoves = struct.unpack('>i', dataGram[60:64])[0]
        self.dot5StatsSingles = struct.unpack('>i', dataGram[64:68])[0]
        self.dot5StatsFreqErrors = struct.unpack('>i', dataGram[68:72])[0]


class sFlowVgCounters():
    "counterData: enterprise = 0, format = 4"

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.dot12InHighPriorityFrames = struct.unpack('>i', dataGram[0:4])[0]
        self.dot12InHighPriorityOctets = struct.unpack('>q', dataGram[4:12])[0]
        self.dot12InNormPriorityFrames = struct.unpack('>i', dataGram[12:16])[0]
        self.dot12InNormPriorityOctets = struct.unpack('>q', dataGram[16:24])[0]
        self.dot12InIPMErrors = struct.unpack('>i', dataGram[24:28])[0]
        self.dot12InOversizeFrameErrors = struct.unpack('>i', dataGram[28:32])[0]
        self.dot12InDataErrors = struct.unpack('>i', dataGram[32:36])[0]
        self.dot12InNullAddressedFrames = struct.unpack('>i', dataGram[36:40])[0]
        self.dot12OutHighPriorityFrames = struct.unpack('>i', dataGram[40:44])[0]
        self.dot12OutHighPriorityOctets = struct.unpack('>q', dataGram[44:52])[0]
        self.dot12TransitionIntoTrainings = struct.unpack('>i', dataGram[52:56])[0]
        self.dot12HCInHighPriorityOctets = struct.unpack('>q', dataGram[56:64])[0]
        self.dot12HCInNormPriorityOctets = struct.unpack('>q', dataGram[64:72])[0]
        self.dot12HCOutHighPriorityOctets = struct.unpack('>q', dataGram[72:80])[0]


class sFlowVLAN: #2-5 (28 bytes)
    "counterData: enterprise = 0, format = 5"

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.vlanID = struct.unpack('>i', dataGram[0:4])[0]
        self.octets = struct.unpack('>q', dataGram[4:12])[0] #64-bit
        self.unicast = struct.unpack('>i', dataGram[12:16])[0]
        self.multicast = struct.unpack('>i', dataGram[16:20])[0]
        self.broadcast = struct.unpack('>i', dataGram[20:24])[0]
        self.discard = struct.unpack('>i', dataGram[24:28])[0]


class sFlowProcessor():
    "counterData: enterprise = 0, format = 1001"

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.cpu5s = struct.unpack('>i', dataGram[0:4])[0]
        self.cpu1m = struct.unpack('>i', dataGram[4:8])[0] 
        self.cpu5m = struct.unpack('>i', dataGram[8:12])[0]
        self.totalMemory = struct.unpack('>q', dataGram[12:20])[0] #64-bit
        self.freeMemory = struct.unpack('>q', dataGram[20:28])[0] #64-bit       


class sFlowOfPort():
    "counterData: enterprise = 0, format = 1004"

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.datapathId = struct.unpack('>i', dataGram[0:8])[0]
        self.portNo = struct.unpack('>i', dataGram[8:12])[0]


class sFlowPortName():
    "counterData: enterprise = 0, format = 1005"

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        nameLength = struct.unpack('>i', dataGram[0:4])[0]
        self.PortName = dataGram[dataPosition:(dataPosition + nameLength)].decode('utf-8')


class sFlowHostDescr():
    "counterData: enterprise = 0, format = 2000"

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        nameLength = min(unpack('>i', dataGram[0:4])[0], 64)
        dataPostion = 4
        self.hostname = dataGram[dataPosition:(dataPosition + nameLength)].decode('utf-8')
        dataPostion += nameLength + (4 - nameLength) % 4
        self.uuid = uuid.UUID(bytes=dataGram[dataPosition:(dataPosition + 16)])
        dataPosition = dataPosition + 16
        self.machineType = struct.unpack('>i', dataGram[dataPosition:(dataPosition + 4)])[0]
        dataPosition = dataPosition + 4
        self.osName = struct.unpack('>i', dataGram[dataPosition:(dataPosition + 4)])[0]
        dataPosition = dataPosition + 4
        nameLength = min(unpack('>i', dataGram[dataPosition:(dataPosition + 4)])[0], 32)
        dataPostion += 4
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
        count = struct.unpack('>i', dataGram[0:4])[0]
        dataPosition = 4
        for a in range(count):
            hostadapter = HostAdapter()
            hostadapter.ifIndex = struct.unpack('>i', dataGram[dataPosition:(dataPosition + 4)])[0]
            dataPosition += 4
            hostadapter.macAddressCount = struct.unpack('>i', dataGram[dataPosition:(dataPosition + 4)])[0]
            dataPosition += 4
            hostadapter.macAddresses = []
            for macAddressNum in range(self.macAddressCount):
                hostadapter.macAddresses.append(binascii.hexlify(dataGram[(dataPosition + macAddressNum * 8):(dataPosition + macAddressNum * 8 + 6)]) ])
            dataPosition += hostadapter.macAddressCount * 8
            self.adapters.append(hostAdapter(stream))


class sFlowHostParent:
    "counterData: enterprise = 0, format = 2002"

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.containerType = struct.unpack('>i', dataGram[0:4])[0]
        self.containerIndex = struct.unpack('>i', dataGram[4:8])[0]


class sFlowHostCPU:
    "counterData: enterprise = 0, format = 2003"

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

class sFlowHostMemory:
    "counterData: enterprise = 0, format = 2004"

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

class sFlowHostDiskIO:
    "counterData: enterprise = 0, format = 2005"

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

class sFlowHostNetIO:
    "counterData: enterprise = 0, format = 2006"

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

class sFlowMib2IP:
    "counterData: enterprise = 0, format = 2007"

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

class sFlowMib2ICMP:
    "counterData: enterprise = 0, format = 2008"

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

class sFlowMib2TCP:
    "counterData: enterprise = 0, format = 2009"

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

class sFlowMib2UDP:
    "counterData: enterprise = 0, format = 2010"

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


class virtNode():
    "counterData: enterprise = 0, format = 2100"

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.mhz = struct.unpack('>i', dataGram[0:4])[0]
        self.cpus = struct.unpack('>i', dataGram[4:8])[0]
        self.memory = struct.unpack('>q', dataGram[8:16])[0]
        self.memoryFree = struct.unpack('>q', dataGram[16:24])[0]
        self.numDomains = struct.unpack('>i', dataGram[24:28])[0]


class virtCpu():
    "counterData: enterprise = 0, format = 2101"

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.state = struct.unpack('>i', dataGram[0:4])[0]
        self.cpuTime = struct.unpack('>i', dataGram[4:8])[0]
        self.nrVirtCpu = struct.unpack('>i', dataGram[8:12])[0]


class virtMemory():
    "counterData: enterprise = 0, format = 2102"

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.memory = struct.unpack('>q', dataGram[0:8])[0]
        self.maxMemory = struct.unpack('>q', dataGram[8:16])[0]


class virtDiskIo():
    "counterData: enterprise = 0, format = 2103"

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.capacity = struct.unpack('>q', dataGram[0:8])[0]
        self.allocation = struct.unpack('>q', dataGram[8:16])[0]
        self.available = struct.unpack('>q', dataGram[16:24])[0]
        self.rdReq = struct.unpack('>i', dataGram[24:28])[0]
        self.rdBytes = struct.unpack('>q', dataGram[28:36])[0]
        self.wrReq = struct.unpack('>i', dataGram[36:40])[0]
        self.wrBytes = struct.unpack('>q', dataGram[40:48])[0]
        self.errs = struct.unpack('>i', dataGram[48:52])[0]


class virtNetIo():
    "counterData: enterprise = 0, format = 2104"

    def __init__(self, length, dataGram):
        self.len = length
        self.data = dataGram
        self.rxBytes = struct.unpack('>q', dataGram[0:8])[0]
        self.rxPackets = struct.unpack('>i', dataGram[8:12])[0]
        self.rxErrs = struct.unpack('>i', dataGram[12:16])[0]
        self.rxDrop = struct.unpack('>i', dataGram[16:20])[0]
        self.txBytes = struct.unpack('>q', dataGram[20:28])[0]
        self.txPackets = struct.unpack('>i', dataGram[28:32])[0]
        self.txErrs = struct.unpack('>i', dataGram[32:36])[0]
        self.txDrop = struct.unpack('>i', dataGram[36:40])[0]