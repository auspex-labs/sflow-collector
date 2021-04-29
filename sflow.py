from struct import unpack
from socket import inet_ntop, AF_INET, AF_INET6
from uuid import UUID


# The sFlow Collector is a class for parsing sFlow data.

# sFlow datagrams contain a header, which may contain samples which may contain records.
# The datagram may not contain a sample, but if it does there will be at least on record.
# The records may have different formats.

# QUESTION (17-06-29) Is the raw data for each block actually needed? What is the cost for preserving them?

# sFlow
#   sample
#       record

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


# IDEA (17-03-07) Sanity check for the fixed length records could be implimented with a simple value check.


class sFlowRecordBase:
    def __init__(self, length, datagram):
        self.len = length
        self.data = datagram

    def __repr__(self):
        return "sFlow Record Type Not Implimented."

    def __len__(self):
        return 1


# Flow Record Types


class sFlowRawPacketHeader:
    "flowData: enterprise = 0, format = 1"

    def __init__(self, length, datagram):
        self.len = length
        self.data = datagram
        self.headerProtocol = unpack(">i", datagram[0:4])[0]
        self.frameLength = unpack(">i", datagram[4:8])[0]
        self.payloadRemoved = unpack(">i", datagram[8:12])[0]
        self.headerSize = unpack(">i", datagram[12:16])[0]
        self.header = datagram[(16) : (16 + self.headerSize)]
        ofset = 0
        self.type = unpack(">H", datagram[36:38])[0]
        if self.type == int(16384):  # if 802.1q info in sample header
            ofset = 4
        self.srcMAC = datagram[22:28].hex("-")
        self.dstMAC = datagram[16:22].hex("-")
        self.srcIp = inet_ntop(AF_INET, datagram[46 - ofset : 50 - ofset])
        self.dstIp = inet_ntop(AF_INET, datagram[50 - ofset : 54 - ofset])
        self.srcPort = unpack(">H", datagram[54 - ofset : 56 - ofset])[0]
        self.dstPort = unpack(">H", datagram[56 - ofset : 58 - ofset])[0]

    def __repr__(self):
        return f"""
            Raw Packet Header:
                Protocol: {self.headerProtocol}
                Frame Length: {self.frameLength}
                Header Size: {self.headerSize}
                Payload Removed: {self.payloadRemoved}
                Header Size: {self.headerSize}
                Source MAC: {self.srcMAC}
                Destination MAC: {self.dstMAC}
                Source IP: {self.srcIp}
                Destination IP: {self.dstIp}
                Source Port: {self.srcPort}
                Destination Port: {self.dstPort}
        """


class sFlowEthernetFrame:
    "flowData: enterprise = 0, format = 2"

    def __init__(self, length, datagram):
        self.len = length
        self.data = datagram
        self.frameLength = unpack(">i", datagram[0:4])[0]
        self.srcMAC = datagram[4:10].hex("-")
        self.dstMAC = datagram[12:18].hex("-")
        self.type = unpack(">i", datagram[20:24])[0]

    def __repr__(self):
        return f"""
            Ethernet Frame:
                Source MAC: {self.srcMAC}
                Destination MAC: {self.dstMAC}
                Frame Type: {self.type}
        """


class sFlowSampledIpv4:
    "flowData: enterprise = 0, format = 3"

    def __init__(self, length, datagram):
        self.len = length
        self.data = datagram
        self.length = unpack(">i", datagram[0:4])[0]
        self.protocol = unpack(">i", datagram[4:8])[0]
        self.srcIp = inet_ntop(AF_INET, datagram[8:12])
        self.dstIp = inet_ntop(AF_INET, datagram[12:16])
        self.srcPort = unpack(">i", datagram[16:20])[0]
        self.dstPort = unpack(">i", datagram[20:24])[0]
        self.tcpFlags = unpack(">i", datagram[24:28])[0]
        self.tos = unpack(">i", datagram[28:32])[0]

    def __repr__(self):
        return f"""
            IPv4 Sample:
                Protocol: {self.protocol}
                Source IP: {self.srcIp}
                Destination IP: {self.dstIp}
                Source Port: {self.srcPort}
                Destination Port: {self.dstPort}
                TCP Flags: {self.tcpFlags}
                Type of Service: {self.tos}
        """


class sFlowSampledIpv6:
    "flowData: enterprise = 0, format = 4"

    def __init__(self, length, datagram):
        self.len = length
        self.data = datagram
        self.length = unpack(">i", datagram[0:4])[0]
        self.protocol = unpack(">i", datagram[4:8])[0]
        self.srcIp = inet_ntop(AF_INET6, datagram[8:24])
        self.dstIp = inet_ntop(AF_INET6, datagram[24:40])
        self.srcPort = unpack(">i", datagram[40:44])[0]
        self.dstPort = unpack(">i", datagram[44:48])[0]
        self.tcpFlags = unpack(">i", datagram[48:52])[0]
        self.priority = unpack(">i", datagram[52:56])[0]

    def __repr__(self):
        return f"""
            IPv6 Sample:
                Length: {self.len}
        """


class sFlowExtendedSwitch:
    "flowData: enterprise = 0, format = 1001"

    def __init__(self, length, datagram):
        self.len = length
        self.data = datagram
        self.srcVLAN = unpack(">i", datagram[0:4])[0]
        self.srcPriority = unpack(">i", datagram[4:8])[0]
        self.dstVLAN = unpack(">i", datagram[8:12])[0]
        self.dstPriority = unpack(">i", datagram[12:16])[0]

    def __repr__(self):
        return f"""
            Extended Switch:
                Length: {self.len}
        """


class sFlowExtendedRouter:
    "flowData: enterprise = 0, format = 1002"

    def __init__(self, length, datagram):
        self.len = length
        self.data = datagram
        self.addressType = unpack(">i", datagram[0:4])[0]
        if self.addressType == 1:
            self.nextHop = inet_ntop(AF_INET, datagram[4:8])
            data_position = 8
        elif self.addressType == 2:
            self.nextHop = inet_ntop(AF_INET6, datagram[4:20])
            data_position = 20
        else:
            self.nextHop = 0
            self.srcMaskLen = 0
            self.dstMaskLen = 0
            return
        self.srcMaskLen = unpack(">i", datagram[data_position : (data_position + 4)])[0]
        data_position += 4
        self.dstMaskLen = unpack(">i", datagram[data_position : (data_position + 4)])[0]

    def __repr__(self):
        return f"""
            Extended Router:
                Length: {self.len}
        """


class sFlowExtendedGateway:
    "flowData: enterprise = 0, format = 1003"

    def __init__(self, length, datagram):
        self.len = length
        self.data = datagram
        self.addressType = unpack(">i", datagram[0:4])[0]
        if self.addressType == 1:
            self.nextHop = inet_ntop(AF_INET, datagram[4:8])
            data_position = 8
        elif self.addressType == 2:
            self.nextHop = inet_ntop(AF_INET6, datagram[4:20])
            data_position = 20
        else:
            self.nextHop = 0
            self.asNumber = 0
            self.srcAutonomousSystemsNumber = 0
            self.srcPeerAutonomousSystemsNumber = 0
            self.asPathType = 0
            self.asPathCount = 0
            self.dstAutonomousSystemsPath = []
            self.communities = []
            self.localpref = 0
            return
        self.asNumber = unpack(">i", datagram[data_position : (data_position + 4)])[0]
        data_position += 4
        self.srcAsNumber = unpack(">i", datagram[data_position : (data_position + 4)])[0]
        data_position += 4
        self.srcPeerAsNumber = unpack(">i", datagram[data_position : (data_position + 4)])[0]
        data_position += 4
        self.asPathType = unpack(">i", datagram[data_position : (data_position + 4)])[0]
        data_position += 4
        self.asPathCount = unpack(">i", datagram[data_position : (data_position + 4)])[0]
        data_position += 4
        self.dstAsPath = unpack(f'>{"i" * self.asPathCount}', datagram[data_position : (data_position + self.asPathCount * 4)])
        data_position += self.asPathCount * 4
        self.communitiesCount = unpack(">i", datagram[data_position : (data_position + 4)])[0]
        data_position += 4
        self.communities = unpack(
            f'>{"i" * self.communitiesCount}', datagram[data_position : (data_position + self.communitiesCount * 4)]
        )
        data_position += self.communitiesCount * 4
        self.localpref = unpack(">i", datagram[data_position : (data_position + 4)])[0]

    def __repr__(self):
        return f"""
            Extended Gateway:
                Length: {self.len}
        """


class sFlowExtendedUser:
    "flowData: enterprise = 0, format = 1004"

    def __init__(self, length, datagram):
        self.len = length
        self.data = datagram
        self.srcCharset = unpack(">i", datagram[0:4])
        name_length = unpack(">i", datagram[4:8])[0]
        self.srcUser = datagram[8 : (8 + name_length)].decode("utf-8")
        data_position = name_length + (4 - name_length) % 4
        self.dstCharset = datagram[data_position : (data_position + name_length)].decode("utf-8")
        data_position += 4
        name_length = unpack(">i", datagram[4:8])[0]
        self.dstUser = datagram[data_position : (data_position + name_length)].decode("utf-8")

    def __repr__(self):
        return f"""
            Extended User:
                Length: {self.len}
        """


class sFlowExtendedUrl:
    "flowData: enterprise = 0, format = 1005"

    def __init__(self, length, datagram):
        self.len = length
        self.data = datagram
        self.direction = unpack(">i", datagram[0:4])[0]
        name_length = min(unpack(">i", datagram[4:8])[0], 255)
        data_position = 8
        self.url = datagram[data_position : (data_position + name_length)].decode("utf-8")
        data_position += name_length + (4 - name_length) % 4
        name_length = min(unpack(">i", datagram[data_position : (data_position + 4)])[0], 255)
        data_position += 4
        self.host = datagram[data_position : (data_position + name_length)].decode("utf-8")
        name_length = unpack(">i", datagram[0:4])[0]
        self.PortName = datagram[data_position : (data_position + name_length)].decode("utf-8")

    def __repr__(self):
        return f"""
            Extended URL:
                Length: {self.len}
        """


class sFlowExtendedMpls:
    "flowData: enterprise = 0, format = 1006"

    def __init__(self, length, datagram):
        self.len = length
        self.data = datagram
        self.addressType = unpack(">i", datagram[0:4])[0]
        data_position = 4
        if self.addressType == 1:
            self.nextHop = inet_ntop(AF_INET, datagram[data_position : (data_position + 4)])
            data_position += 4
        elif self.addressType == 2:
            self.nextHop = inet_ntop(AF_INET6, datagram[data_position : (data_position + 16)])
            data_position += 16
        else:
            self.nextHop = 0
            self.inLabelStackCount = 0
            self.inLabelStack = []
            self.outLabelStackCount = 0
            self.outLabelStack = []
            return
        self.inLabelStackCount = unpack(">i", datagram[data_position : (data_position + 4)])[0]
        data_position += 4
        self.inLabelStack = unpack(
            f'>{"i" * self.inLabelStackCount}', datagram[data_position : (data_position + self.inLabelStackCount * 4)]
        )
        data_position += self.inLabelStackCount * 4
        self.outLabelStackCount = unpack(">i", datagram[data_position : (data_position + 4)])[0]
        data_position += 4
        self.outLabelStack = unpack(
            f'>{"i" * self.outLabelStackCount}', datagram[data_position : (data_position + self.outLabelStackCount * 4)]
        )

    def __repr__(self):
        return f"""
            Extended MPLS:
                Length: {self.len}
        """


class sFlowExtendedNat:
    "flowData: enterprise = 0, format = 1007"

    def __init__(self, length, datagram):
        self.len = length
        self.data = datagram
        self.srcAddressType = unpack(">i", datagram[0:4])[0]
        data_position = 4
        if self.srcAddressType == 1:
            self.srcAddress = inet_ntop(AF_INET, datagram[data_position : (data_position + 4)])
            data_position += 4
        elif self.srcAddressType == 2:
            self.srcAddress = inet_ntop(AF_INET6, datagram[data_position : (data_position + 16)])
            data_position += 16
        else:
            self.srcAddress = 0
            self.dstAddress = 0
            return
        self.dstAddressType = unpack(">i", datagram[0:4])[0]
        data_position += 4
        if self.dstAddressType == 1:
            self.dstAddress = inet_ntop(AF_INET, datagram[data_position : (data_position + 4)])
            data_position += 4
        elif self.dstAddressType == 2:
            self.dstAddress = inet_ntop(AF_INET6, datagram[data_position : (data_position + 16)])
            data_position += 16
        else:
            self.dstAddress = 0
            return

    def __repr__(self):
        return f"""
            Extended NAT:
                Length: {self.len}
        """


class sFlowExtendedMplsTunnel:
    "flowData: enterprise = 0, format = 1008"

    def __init__(self, length, datagram):
        self.len = length
        self.data = datagram
        name_length = min(unpack(">i", datagram[0:4])[0], 255)
        self.host = datagram[4 : (4 + name_length)].decode("utf-8")
        data_position = 4 + name_length + (4 - name_length) % 4
        self.tunnelId = unpack(">i", datagram[data_position : (data_position + 4)])[0]
        data_position += 4
        self.tunnelCos = unpack(">i", datagram[data_position : (data_position + 4)])[0]

    def __repr__(self):
        return f"""
            Extended MPLS Tunnel:
                Length: {self.len}
        """


class sFlowExtendedMplsVc:
    "flowData: enterprise = 0, format = 1009"

    def __init__(self, length, datagram):
        self.len = length
        self.data = datagram
        name_length = min(unpack(">i", datagram[0:4])[0], 255)
        self.vcInstanceName = datagram[4 : (4 + name_length)].decode("utf-8")
        data_position = 4 + name_length + (4 - name_length) % 4
        self.vllVcId = unpack(">i", datagram[data_position : (data_position + 4)])[0]
        data_position += 4
        self.vcLabelCos = unpack(">i", datagram[data_position : (data_position + 4)])[0]

    def __repr__(self):
        return f"""
            Extended MPLS Virtual Circuit:
                Length: {self.len}
        """


class sFlowExtendedMpls_FTN:
    "flowData: enterprise = 0, format = 1010"

    def __init__(self, length, datagram):
        self.len = length
        self.data = datagram
        name_length = min(unpack(">i", datagram[0:4])[0], 255)
        self.mplsFTNDescr = datagram[4 : (4 + name_length)].decode("utf-8")
        data_position = 4 + name_length + (4 - name_length) % 4
        self.mplsFTNMask = unpack(">i", datagram[data_position : (data_position + 4)])[0]

    def __repr__(self):
        return f"""
            Extended MPLS FTN:
                Length: {self.len}
        """


class sFlowExtendedMpls_LDP_FEC:
    "flowData: enterprise = 0, format = 1011"

    def __init__(self, length, datagram):
        self.len = length
        self.data = datagram
        self.mplsFecAddrPrefixLength = unpack(">i", datagram)[0]

    def __repr__(self):
        return f"""
            Extended MPLS LDP FEC:
                Length: {self.len}
        """


class sFlowExtendedVlantunnel:
    "flowData: enterprise = 0, format = 1012"

    def __init__(self, length, datagram):
        self.len = length
        self.data = datagram
        stack_count = unpack(">i", datagram[0:4])[0]
        self.stack = unpack(f'>{"i" * stack_count}', datagram[4 : (4 + stack_count * 4)])

    def __repr__(self):
        return f"""
            Extended VLAN Tunnel:
                Length: {self.len}
        """


class sFlowExtendedSocketIpv4:
    "flowData: enterprise = 0, format = 2100"

    def __init__(self, length, datagram):
        self.len = length
        self.data = datagram
        self.protocol = unpack(">i", datagram[0:4])[0]
        self.localIp = inet_ntop(AF_INET, datagram[4:8])
        self.remoteIp = inet_ntop(AF_INET, datagram[8:12])
        self.localPort = unpack(">i", datagram[12:16])[0]
        self.remotePort = unpack(">i", datagram[16:20])[0]

    def __repr__(self):
        return f"""
            Extended IPv4 Socket:
                Length: {self.len}
        """


class sFlowExtendedSocketIpv6:
    "flowData: enterprise = 0, format = 2101"

    def __init__(self, length, datagram):
        self.len = length
        self.data = datagram
        self.protocol = unpack(">i", datagram[0:4])[0]
        self.localIp = inet_ntop(AF_INET6, datagram[4:20])
        self.remoteIp = inet_ntop(AF_INET6, datagram[20:36])
        self.localPort = unpack(">i", datagram[36:40])[0]
        self.remotePort = unpack(">i", datagram[40:44])[0]

    def __repr__(self):
        return f"""
            Extended IPv6 Socket:
                Length: {self.len}
        """


# Counter Record Types


class sFlowIfCounters:
    "counterData: enterprise = 0, format = 1"

    def __init__(self, length, datagram):
        self.len = length
        self.data = datagram
        self.index = unpack(">i", datagram[0:4])[0]
        self.type = unpack(">i", datagram[4:8])[0]
        self.speed = unpack(">q", datagram[8:16])[0]  # 64-bit
        self.direction = unpack(">i", datagram[16:20])[0]
        self.status = unpack(">i", datagram[20:24])[0]  # This is really a 2-bit value
        self.inputOctets = unpack(">q", datagram[24:32])[0]  # 64-bit
        self.inputPackets = unpack(">i", datagram[32:36])[0]
        self.inputMulticast = unpack(">i", datagram[36:40])[0]
        self.inputBroadcast = unpack(">i", datagram[40:44])[0]
        self.inputDiscarded = unpack(">i", datagram[44:48])[0]
        self.inputErrors = unpack(">i", datagram[48:52])[0]
        self.inputUnknown = unpack(">i", datagram[52:56])[0]
        self.outputOctets = unpack(">q", datagram[56:64])[0]  # 64-bit
        self.outputPackets = unpack(">i", datagram[64:68])[0]
        self.outputMulticast = unpack(">i", datagram[68:72])[0]
        self.outputBroadcast = unpack(">i", datagram[72:76])[0]
        self.outputDiscarded = unpack(">i", datagram[76:80])[0]
        self.outputErrors = unpack(">i", datagram[80:84])[0]
        self.promiscuous = unpack(">i", datagram[84:88])[0]

    def __repr__(self) -> str:
        return f"""
            Interface Counters:
                Length: {self.len}
                Index: {self.index}
                Type: {self.type}
                Speed: {self.speed}
                Direction: {self.direction}
                Status: {self.status}
                In Octets: {self.inputOctets}
                In Packets: {self.inputPackets}
                In Multicast: {self.inputMulticast}
                In Broadcast: {self.inputBroadcast}
                In Discards: {self.inputDiscarded}
                In Errors: {self.inputErrors}
                In Unknown: {self.inputUnknown}
                Out Octets: {self.outputOctets}
                Out Packets: {self.outputPackets}
                Out Multicast: {self.outputMulticast}
                Out Broadcast: {self.outputBroadcast}
                Out Discard: {self.outputDiscarded}
                Out Errors: {self.outputErrors}
                Promiscuous: {self.promiscuous}
        """


class sFlowEthernetInterface:
    "counterData: enterprise = 0, format = 2"

    def __init__(self, length, datagram):
        self.len = length
        self.data = datagram
        self.alignmentError = unpack(">i", datagram[0:4])[0]
        self.fcsError = unpack(">i", datagram[4:8])[0]
        self.singleCollision = unpack(">i", datagram[8:12])[0]
        self.multipleCollision = unpack(">i", datagram[12:16])[0]
        self.sqeTest = unpack(">i", datagram[16:20])[0]
        self.deferred = unpack(">i", datagram[20:24])[0]
        self.lateCollision = unpack(">i", datagram[24:28])[0]
        self.excessiveCollision = unpack(">i", datagram[28:32])[0]
        self.internalTransmitError = unpack(">i", datagram[32:36])[0]
        self.carrierSenseError = unpack(">i", datagram[36:40])[0]
        self.frameTooLong = unpack(">i", datagram[40:44])[0]
        self.internalReceiveError = unpack(">i", datagram[44:48])[0]
        self.symbolError = unpack(">i", datagram[48:52])[0]

    def __repr__(self):
        return f"""
            Ethernet Counters:
                Length: {self.len}
        """


class sFlowTokenringCounters:
    "counterData: enterprise = 0, format = 3"

    def __init__(self, length, datagram):
        self.len = length
        self.data = datagram
        self.dot5StatsLineErrors = unpack(">i", datagram[0:4])[0]
        self.dot5StatsBurstErrors = unpack(">i", datagram[4:8])[0]
        self.dot5StatsACErrors = unpack(">i", datagram[8:12])[0]
        self.dot5StatsAbortTransErrors = unpack(">i", datagram[12:16])[0]
        self.dot5StatsInternalErrors = unpack(">i", datagram[16:20])[0]
        self.dot5StatsLostFrameErrors = unpack(">i", datagram[20:24])[0]
        self.dot5StatsReceiveCongestions = unpack(">i", datagram[24:28])[0]
        self.dot5StatsFrameCopiedErrors = unpack(">i", datagram[28:32])[0]
        self.dot5StatsTokenErrors = unpack(">i", datagram[32:36])[0]
        self.dot5StatsSoftErrors = unpack(">i", datagram[36:40])[0]
        self.dot5StatsHardErrors = unpack(">i", datagram[40:44])[0]
        self.dot5StatsSignalLoss = unpack(">i", datagram[44:48])[0]
        self.dot5StatsTransmitBeacons = unpack(">i", datagram[48:52])[0]
        self.dot5StatsRecoverys = unpack(">i", datagram[52:56])[0]
        self.dot5StatsLobeWires = unpack(">i", datagram[56:60])[0]
        self.dot5StatsRemoves = unpack(">i", datagram[60:64])[0]
        self.dot5StatsSingles = unpack(">i", datagram[64:68])[0]
        self.dot5StatsFreqErrors = unpack(">i", datagram[68:72])[0]

    def __repr__(self):
        return f"""
            Token Ring Counters:
                Length: {self.len}
        """


class sFlowVgCounters:
    "counterData: enterprise = 0, format = 4"

    def __init__(self, length, datagram):
        self.len = length
        self.data = datagram
        self.dot12InHighPriorityFrames = unpack(">i", datagram[0:4])[0]
        self.dot12InHighPriorityOctets = unpack(">q", datagram[4:12])[0]
        self.dot12InNormPriorityFrames = unpack(">i", datagram[12:16])[0]
        self.dot12InNormPriorityOctets = unpack(">q", datagram[16:24])[0]
        self.dot12InIPMErrors = unpack(">i", datagram[24:28])[0]
        self.dot12InOversizeFrameErrors = unpack(">i", datagram[28:32])[0]
        self.dot12InDataErrors = unpack(">i", datagram[32:36])[0]
        self.dot12InNullAddressedFrames = unpack(">i", datagram[36:40])[0]
        self.dot12OutHighPriorityFrames = unpack(">i", datagram[40:44])[0]
        self.dot12OutHighPriorityOctets = unpack(">q", datagram[44:52])[0]
        self.dot12TransitionIntoTrainings = unpack(">i", datagram[52:56])[0]
        self.dot12HCInHighPriorityOctets = unpack(">q", datagram[56:64])[0]
        self.dot12HCInNormPriorityOctets = unpack(">q", datagram[64:72])[0]
        self.dot12HCOutHighPriorityOctets = unpack(">q", datagram[72:80])[0]

    def __repr__(self):
        return f"""
            VG Counters:
                Length: {self.len}
        """


class sFlowVLAN:
    "counterData: enterprise = 0, format = 5"

    def __init__(self, length, datagram):
        self.len = length
        self.data = datagram
        self.vlanID = unpack(">i", datagram[0:4])[0]
        self.octets = unpack(">q", datagram[4:12])[0]  # 64-bit
        self.unicast = unpack(">i", datagram[12:16])[0]
        self.multicast = unpack(">i", datagram[16:20])[0]
        self.broadcast = unpack(">i", datagram[20:24])[0]
        self.discard = unpack(">i", datagram[24:28])[0]

    def __repr__(self):
        return f"""
            VLAN Counters:
                Length: {self.len}
        """


class sFlowProcessor:
    "counterData: enterprise = 0, format = 1001"

    def __init__(self, length, datagram):
        self.len = length
        self.data = datagram
        self.cpu5s = unpack(">i", datagram[0:4])[0]
        self.cpu1m = unpack(">i", datagram[4:8])[0]
        self.cpu5m = unpack(">i", datagram[8:12])[0]
        self.totalMemory = unpack(">q", datagram[12:20])[0]  # 64-bit
        self.freeMemory = unpack(">q", datagram[20:28])[0]  # 64-bit

    def __repr__(self):
        return f"""
            Processor Counters:
                Length: {self.len}
        """


class sFlowOfPort:
    "counterData: enterprise = 0, format = 1004"

    def __init__(self, length, datagram):
        self.len = length
        self.data = datagram
        self.datapathId = unpack(">i", datagram[0:8])[0]
        self.portNo = unpack(">i", datagram[8:12])[0]

    def __repr__(self):
        return f"""
            OpenFlow Port:
                Length: {self.len}
        """


class sFlowPortName:
    "counterData: enterprise = 0, format = 1005"

    def __init__(self, length, datagram):
        self.len = length
        self.data = datagram
        name_length = unpack(">i", datagram[0:4])[0]
        self.PortName = datagram[4 : (4 + name_length)].decode("utf-8")

    def __repr__(self):
        return f"""
            OpenFlow Port Name:
                Length: {self.len}
        """


class sFlowHostDescr:
    "counterData: enterprise = 0, format = 2000"

    def __init__(self, length, datagram):
        self.len = length
        self.data = datagram
        name_length = min(unpack(">i", datagram[0:4])[0], 64)
        data_position = 4
        self.hostname = datagram[data_position : (data_position + name_length)].decode("utf-8")
        data_position += name_length + (4 - name_length) % 4
        self.uuid = UUID(bytes=datagram[data_position : (data_position + 16)])
        data_position = data_position + 16
        self.machineType = unpack(">i", datagram[data_position : (data_position + 4)])[0]
        data_position = data_position + 4
        self.osName = unpack(">i", datagram[data_position : (data_position + 4)])[0]
        data_position = data_position + 4
        name_length = min(unpack(">i", datagram[data_position : (data_position + 4)])[0], 32)
        data_position += 4
        self.osRelease = datagram[data_position : (data_position + name_length)].decode("utf-8")

    def __repr__(self):
        return f"""
            Host Description:
                Length: {self.len}
        """


class sFlowHostAdapters:
    "counterData: enterprise = 0, format = 2001"

    class hostAdapter:
        def __init__(self):
            self.ifIndex = None
            self.macAddressCount = None
            self.macAddresses = None

    def __init__(self, length, datagram):
        self.len = length
        self.data = datagram
        self.adapters = []
        host_adapter_count = unpack(">i", datagram[0:4])[0]
        data_position = 4
        for _ in range(host_adapter_count):
            hostadapter = self.hostAdapter()
            hostadapter.ifIndex = unpack(">i", datagram[data_position : (data_position + 4)])[0]
            data_position += 4
            hostadapter.macAddressCount = unpack(">i", datagram[data_position : (data_position + 4)])[0]
            data_position += 4
            hostadapter.macAddresses = []
            for mac_address in range(hostadapter.macAddressCount):
                hostadapter.macAddresses.append(datagram[(data_position + mac_address * 8) : (data_position + mac_address * 8 + 6)]).hex("-")
            data_position += hostadapter.macAddressCount * 8
            self.adapters.append(hostadapter)

    def __repr__(self):
        return f"""
            Host Adapters:
                Length: {self.len}
        """


class sFlowHostParent:
    "counterData: enterprise = 0, format = 2002"

    def __init__(self, length, datagram):
        self.len = length
        self.data = datagram
        self.containerType = unpack(">i", datagram[0:4])[0]
        self.containerIndex = unpack(">i", datagram[4:8])[0]

    def __repr__(self):
        return f"""
            Host Parent:
                Length: {self.len}
        """


class sFlowHostCPU:
    "counterData: enterprise = 0, format = 2003"

    def __init__(self, length, datagram):
        self.len = length
        self.data = datagram
        self.avgLoad1 = unpack(">f", datagram[0:4])[0]  # Floating Point
        self.avgLoad5 = unpack(">f", datagram[4:8])[0]  # Floating Point
        self.avgLoad15 = unpack(">f", datagram[8:12])[0]  # Floating Point
        self.runProcess = unpack(">i", datagram[12:16])[0]
        self.totalProcess = unpack(">i", datagram[16:20])[0]
        self.numCPU = unpack(">i", datagram[20:24])[0]
        self.mhz = unpack(">i", datagram[24:28])[0]
        self.uptime = unpack(">i", datagram[28:32])[0]
        self.timeUser = unpack(">i", datagram[32:36])[0]
        self.timeNices = unpack(">i", datagram[36:40])[0]
        self.timeKennal = unpack(">i", datagram[40:44])[0]
        self.timeIdle = unpack(">i", datagram[44:48])[0]
        self.timeIO = unpack(">i", datagram[48:52])[0]
        self.timeInterrupt = unpack(">i", datagram[52:56])[0]
        self.timeSoftInterrupt = unpack(">i", datagram[56:60])[0]
        self.interrupt = unpack(">i", datagram[60:64])[0]
        self.contextSwitch = unpack(">i", datagram[64:68])[0]
        self.virtualInstance = unpack(">i", datagram[68:72])[0]
        self.guestOS = unpack(">i", datagram[72:76])[0]
        self.guestNice = unpack(">i", datagram[76:80])[0]

    def __repr__(self):
        return f"""
            Host CPU Counters:
                Length: {self.len}
        """


class sFlowHostMemory:
    "counterData: enterprise = 0, format = 2004"

    def __init__(self, length, datagram):
        self.len = length
        self.data = datagram
        self.memTotal = unpack(">q", datagram[0:8])[0]  # 64-bit
        self.memFree = unpack(">q", datagram[8:16])[0]  # 64-bit
        self.memShared = unpack(">q", datagram[16:24])[0]  # 64-bit
        self.memBuffers = unpack(">q", datagram[24:32])[0]  # 64-bit
        self.memCache = unpack(">q", datagram[32:40])[0]  # 64-bit
        self.swapTotal = unpack(">q", datagram[40:48])[0]  # 64-bit
        self.swapFree = unpack(">q", datagram[48:56])[0]  # 64-bit
        self.pageIn = unpack(">i", datagram[56:60])[0]
        self.pageOut = unpack(">i", datagram[60:64])[0]
        self.swapIn = unpack(">i", datagram[64:68])[0]
        self.swapOut = unpack(">i", datagram[68:72])[0]

    def __repr__(self):
        return f"""
            Host Memory Counters:
                Length: {self.len}
        """


class sFlowHostDiskIO:
    "counterData: enterprise = 0, format = 2005"

    def __init__(self, length, datagram):
        self.len = length
        self.data = datagram
        self.diskTotal = unpack(">q", datagram[0:8])[0]  # 64-bit
        self.diskFree = unpack(">q", datagram[8:16])[0]  # 64-bit
        self.partMaxused = (unpack(">i", datagram[16:20])[0]) / float(100)
        self.read = unpack(">i", datagram[20:24])[0]
        self.readByte = unpack(">q", datagram[24:32])[0]  # 64-bit
        self.readTime = unpack(">i", datagram[32:36])[0]
        self.write = unpack(">i", datagram[36:40])[0]
        self.writeByte = unpack(">q", datagram[40:48])[0]  # 64-bit
        self.writeTime = unpack(">i", datagram[48:52])[0]

    def __repr__(self):
        return f"""
            Host Disk I/O Counters:
                Length: {self.len}
        """


class sFlowHostNetIO:
    "counterData: enterprise = 0, format = 2006"

    def __init__(self, length, datagram):
        self.len = length
        self.data = datagram
        self.inByte = unpack(">q", datagram[0:8])[0]  # 64-bit
        self.inPacket = unpack(">i", datagram[8:12])[0]
        self.inError = unpack(">i", datagram[12:16])[0]
        self.inDrop = unpack(">i", datagram[16:20])[0]
        self.outByte = unpack(">q", datagram[20:28])[0]  # 64-bit
        self.outPacket = unpack(">i", datagram[28:32])[0]
        self.outError = unpack(">i", datagram[32:36])[0]
        self.outDrop = unpack(">i", datagram[36:40])[0]

    def __repr__(self):
        return f"""
            Host Network I/O Counters:
                Length: {self.len}
        """


class sFlowMib2IP:
    "counterData: enterprise = 0, format = 2007"

    def __init__(self, length, datagram):
        self.len = length
        self.data = datagram
        self.forwarding = unpack(">i", datagram[0:4])[0]
        self.defaultTTL = unpack(">i", datagram[4:8])[0]
        self.inReceives = unpack(">i", datagram[8:12])[0]
        self.inHeaderErrors = unpack(">i", datagram[12:16])[0]
        self.inAddressErrors = unpack(">i", datagram[16:20])[0]
        self.inForwardDatagrams = unpack(">i", datagram[20:24])[0]
        self.inUnknownProtocols = unpack(">i", datagram[24:28])[0]
        self.inDiscards = unpack(">i", datagram[28:32])[0]
        self.inDelivers = unpack(">i", datagram[32:36])[0]
        self.outRequests = unpack(">i", datagram[36:40])[0]
        self.outDiscards = unpack(">i", datagram[40:44])[0]
        self.outNoRoutes = unpack(">i", datagram[44:48])[0]
        self.reassemblyTimeout = unpack(">i", datagram[48:52])[0]
        self.reassemblyRequired = unpack(">i", datagram[52:56])[0]
        self.reassemblyOkay = unpack(">i", datagram[56:60])[0]
        self.reassemblyFail = unpack(">i", datagram[60:64])[0]
        self.fragmentOkay = unpack(">i", datagram[64:68])[0]
        self.fragmentFail = unpack(">i", datagram[68:72])[0]
        self.fragmentCreate = unpack(">i", datagram[72:76])[0]

    def __repr__(self):
        return f"""
            MIB2 IP Counters:
                Length: {self.len}
        """


class sFlowMib2ICMP:
    "counterData: enterprise = 0, format = 2008"

    def __init__(self, length, datagram):
        self.len = length
        self.data = datagram
        self.inMessage = unpack(">i", datagram[0:4])[0]
        self.inError = unpack(">i", datagram[4:8])[0]
        self.inDestinationUnreachable = unpack(">i", datagram[8:12])[0]
        self.inTimeExceeded = unpack(">i", datagram[12:16])[0]
        self.inParameterProblem = unpack(">i", datagram[16:20])[0]
        self.inSourceQuence = unpack(">i", datagram[20:24])[0]
        self.inRedirect = unpack(">i", datagram[24:28])[0]
        self.inEcho = unpack(">i", datagram[28:32])[0]
        self.inEchoReply = unpack(">i", datagram[32:36])[0]
        self.inTimestamp = unpack(">i", datagram[36:40])[0]
        self.inAddressMask = unpack(">i", datagram[40:44])[0]
        self.inAddressMaskReply = unpack(">i", datagram[44:48])[0]
        self.outMessage = unpack(">i", datagram[48:52])[0]
        self.outError = unpack(">i", datagram[52:56])[0]
        self.outDestinationUnreachable = unpack(">i", datagram[56:60])[0]
        self.outTimeExceeded = unpack(">i", datagram[60:64])[0]
        self.outParameterProblem = unpack(">i", datagram[64:68])[0]
        self.outSourceQuence = unpack(">i", datagram[68:72])[0]
        self.outRedirect = unpack(">i", datagram[72:76])[0]
        self.outEcho = unpack(">i", datagram[76:80])[0]
        self.outEchoReply = unpack(">i", datagram[80:84])[0]
        self.outTimestamp = unpack(">i", datagram[84:88])[0]
        self.outTimestampReply = unpack(">i", datagram[88:92])[0]
        self.outAddressMask = unpack(">i", datagram[92:96])[0]
        self.outAddressMaskReplay = unpack(">i", datagram[96:100])[0]

    def __repr__(self):
        return f"""
            MIB2 ICMP Counters:
                Length: {self.len}
        """


class sFlowMib2TCP:
    "counterData: enterprise = 0, format = 2009"

    def __init__(self, length, datagram):
        self.len = length
        self.data = datagram
        self.algorithm = unpack(">i", datagram[0:4])[0]
        self.rtoMin = unpack(">i", datagram[4:8])[0]
        self.rtoMax = unpack(">i", datagram[8:12])[0]
        self.maxConnection = unpack(">i", datagram[12:16])[0]
        self.activeOpen = unpack(">i", datagram[16:20])[0]
        self.passiveOpen = unpack(">i", datagram[20:24])[0]
        self.attemptFail = unpack(">i", datagram[24:28])[0]
        self.establishedReset = unpack(">i", datagram[28:32])[0]
        self.currentEstablished = unpack(">i", datagram[32:36])[0]
        self.inSegment = unpack(">i", datagram[36:40])[0]
        self.outSegment = unpack(">i", datagram[40:44])[0]
        self.retransmitSegment = unpack(">i", datagram[44:48])[0]
        self.inError = unpack(">i", datagram[48:52])[0]
        self.outReset = unpack(">i", datagram[52:56])[0]
        self.inCsumError = unpack(">i", datagram[56:60])[0]

    def __repr__(self):
        return f"""
            MIB2 TCP Counters:
                Length: {self.len}
        """


class sFlowMib2UDP:
    "counterData: enterprise = 0, format = 2010"

    def __init__(self, length, datagram):
        self.len = length
        self.data = datagram
        self.inDatagrams = unpack(">i", datagram[0:4])[0]
        self.noPorts = unpack(">i", datagram[4:8])[0]
        self.inErrors = unpack(">i", datagram[8:12])[0]
        self.outDatagrams = unpack(">i", datagram[12:16])[0]
        self.receiveBufferError = unpack(">i", datagram[16:20])[0]
        self.sendBufferError = unpack(">i", datagram[20:24])[0]
        self.inCheckSumError = unpack(">i", datagram[24:28])[0]

    def __repr__(self):
        return f"""
            MIB2 UDP Counters:
                Length: {self.len}
        """


class sFlowVirtNode:
    "counterData: enterprise = 0, format = 2100"

    def __init__(self, length, datagram):
        self.len = length
        self.data = datagram
        self.mhz = unpack(">i", datagram[0:4])[0]
        self.cpus = unpack(">i", datagram[4:8])[0]
        self.memory = unpack(">q", datagram[8:16])[0]
        self.memoryFree = unpack(">q", datagram[16:24])[0]
        self.numDomains = unpack(">i", datagram[24:28])[0]

    def __repr__(self):
        return f"""
            Virtual Node Counters:
                Length: {self.len}
        """


class sFlowVirtCPU:
    "counterData: enterprise = 0, format = 2101"

    def __init__(self, length, datagram):
        self.len = length
        self.data = datagram
        self.state = unpack(">i", datagram[0:4])[0]
        self.cpuTime = unpack(">i", datagram[4:8])[0]
        self.nrVirtCpu = unpack(">i", datagram[8:12])[0]

    def __repr__(self):
        return f"""
            Virtual CPU Counters:
                Length: {self.len}
        """


class sFlowVirtMemory:
    "counterData: enterprise = 0, format = 2102"

    def __init__(self, length, datagram):
        self.len = length
        self.data = datagram
        self.memory = unpack(">q", datagram[0:8])[0]
        self.maxMemory = unpack(">q", datagram[8:16])[0]

    def __repr__(self):
        return f"""
            Virtual Memory Counters:
                Length: {self.len}
        """


class sFlowVirtDiskIO:
    "counterData: enterprise = 0, format = 2103"

    def __init__(self, length, datagram):
        self.len = length
        self.data = datagram
        self.capacity = unpack(">q", datagram[0:8])[0]
        self.allocation = unpack(">q", datagram[8:16])[0]
        self.available = unpack(">q", datagram[16:24])[0]
        self.rdReq = unpack(">i", datagram[24:28])[0]
        self.rdBytes = unpack(">q", datagram[28:36])[0]
        self.wrReq = unpack(">i", datagram[36:40])[0]
        self.wrBytes = unpack(">q", datagram[40:48])[0]
        self.errs = unpack(">i", datagram[48:52])[0]

    def __repr__(self):
        return f"""
            Virtual Disk IO Counters:
                Length: {self.len}
        """


class sFlowVirtNetIO:
    "counterData: enterprise = 0, format = 2104"

    def __init__(self, length, datagram):
        self.len = length
        self.data = datagram
        self.rxBytes = unpack(">q", datagram[0:8])[0]
        self.rxPackets = unpack(">i", datagram[8:12])[0]
        self.rxErrs = unpack(">i", datagram[12:16])[0]
        self.rxDrop = unpack(">i", datagram[16:20])[0]
        self.txBytes = unpack(">q", datagram[20:28])[0]
        self.txPackets = unpack(">i", datagram[28:32])[0]
        self.txErrs = unpack(">i", datagram[32:36])[0]
        self.txDrop = unpack(">i", datagram[36:40])[0]

    def __repr__(self):
        return f"""
            Virtual Network IO Counters:
                Length: {self.len}
        """


s_flow_record_format = {
    (1, 0, 1): sFlowRawPacketHeader,
    (1, 0, 2): sFlowEthernetFrame,
    (1, 0, 3): sFlowSampledIpv4,
    (1, 0, 4): sFlowSampledIpv6,
    (1, 0, 1001): sFlowExtendedSwitch,
    (1, 0, 1002): sFlowExtendedRouter,
    (1, 0, 1003): sFlowExtendedGateway,
    (1, 0, 1004): sFlowExtendedUser,
    (1, 0, 1005): sFlowExtendedUrl,
    (1, 0, 1006): sFlowExtendedMpls,
    (1, 0, 1007): sFlowExtendedNat,
    (1, 0, 1008): sFlowExtendedMplsTunnel,
    (1, 0, 1009): sFlowExtendedMplsVc,
    (1, 0, 1010): sFlowExtendedMpls_FTN,
    (1, 0, 1011): sFlowExtendedMpls_LDP_FEC,
    (1, 0, 1012): sFlowExtendedVlantunnel,
    (1, 0, 2100): sFlowExtendedSocketIpv4,
    (1, 0, 2101): sFlowExtendedSocketIpv6,
    (2, 0, 1): sFlowIfCounters,
    (2, 0, 2): sFlowEthernetInterface,
    (2, 0, 3): sFlowTokenringCounters,
    (2, 0, 4): sFlowVgCounters,
    (2, 0, 5): sFlowVLAN,
    (2, 0, 1001): sFlowProcessor,
    (2, 0, 1004): sFlowOfPort,
    (2, 0, 1005): sFlowPortName,
    (2, 0, 2000): sFlowHostDescr,
    (2, 0, 2001): sFlowHostAdapters,
    (2, 0, 2002): sFlowHostParent,
    (2, 0, 2003): sFlowHostCPU,
    (2, 0, 2004): sFlowHostMemory,
    (2, 0, 2005): sFlowHostDiskIO,
    (2, 0, 2006): sFlowHostNetIO,
    (2, 0, 2007): sFlowMib2IP,
    (2, 0, 2008): sFlowMib2ICMP,
    (2, 0, 2009): sFlowMib2TCP,
    (2, 0, 2010): sFlowMib2UDP,
    (2, 0, 2100): sFlowVirtNode,
    (2, 0, 2101): sFlowVirtCPU,
    (2, 0, 2102): sFlowVirtMemory,
    (2, 0, 2103): sFlowVirtDiskIO,
    (2, 0, 2104): sFlowVirtNetIO,
}

# sFlow Record class.


class sFlowRecord:
    """sFlowRecord class:"""

    def __init__(self, header, length, sampleType, datagram):
        self.header = header
        self.enterprise, self.format = divmod(self.header, 4096)
        self.len = length
        self.sampleType = sampleType
        self.datagram = datagram
        self.data = s_flow_record_format.get((sampleType, self.enterprise, self.format), sFlowRecordBase)(length, datagram)


# sFlow Sample class.


class sFlowSample:
    """sFlowSample class:

    sequenceNumber:  Incremented with each flow sample generated by this source_id.
    sourceType:  sFlowDataSource type
    sourceIndex:  sFlowDataSource index
    sampleRate:  sFlowPacketSamplingRate
    samplePool:  Total number of packets that could have been sampled
    drops:  Number of times that the sFlow agent detected that a packet marked to be sampled was dropped due to lack of resources.
    inputIfFormat:  Interface format packet was received on.
    inputIfValue:  Interface value packet was received on.
    outputIfFormat:  Interface format packet was sent on.
    outputIfValue:  Interface value packet was sent on.
    recordCount:  Number of records
    records:  A list of information about sampled packets.
    """

    def __init__(self, header, sample_size, datagram):

        self.len = sample_size
        self.data = datagram

        sample_header = unpack(">i", header)[0]
        self.enterprise, self.sampleType = divmod(sample_header, 4096)
        # 0 sample_data / 1 flow_data (single) / 2 counter_data (single)
        #             / 3 flow_data (expanded) / 4 counter_data (expanded)

        self.sequence = unpack(">i", datagram[0:4])[0]

        if self.sampleType in [1, 2]:
            sample_source = unpack(">i", datagram[4:8])[0]
            self.sourceType, self.sourceIndex = divmod(sample_source, 16777216)
            data_position = 8
        elif self.sampleType in [3, 4]:
            self.sourceType, self.sourceIndex = unpack(">ii", datagram[4:12])
            data_position = 12
        else:
            pass  # sampleTypeError
        self.records = []

        if self.sampleType in [1, 3]:  # Flow
            self.sampleRate, self.samplePool, self.droppedPackets = unpack(">iii", datagram[data_position : (data_position + 12)])
            data_position += 12
            if self.sampleType == 1:
                input_interface, output_interface = unpack(">ii", datagram[(data_position) : (data_position + 8)])
                data_position += 8
                self.inputIfFormat, self.inputIfValue = divmod(input_interface, 1073741824)
                self.outputIfFormat, self.outputIfValue = divmod(output_interface, 1073741824)
            elif self.sampleType == 3:
                self.inputIfFormat, self.inputIfValue, self.outputIfFormat, self.outputIfValue = unpack(
                    ">ii", datagram[data_position : (data_position + 16)]
                )
                data_position += 16
            self.recordCount = unpack(">i", datagram[data_position : data_position + 4])[0]
            data_position += 4

        elif self.sampleType in [2, 4]:  # Counters
            self.recordCount = unpack(">i", datagram[data_position : (data_position + 4)])[0]
            data_position += 4
            self.sampleRate = 0
            self.samplePool = 0
            self.droppedPackets = 0
            self.inputIfFormat = 0
            self.inputIfValue = 0
            self.outputIfFormat = 0
            self.outputIfValue = 0
        else:  # sampleTypeError
            self.recordCount = 0
        for _ in range(self.recordCount):
            record_header = unpack(">i", datagram[(data_position) : (data_position + 4)])[0]
            record_size = unpack(">i", datagram[(data_position + 4) : (data_position + 8)])[0]
            record_data = datagram[(data_position + 8) : (data_position + record_size + 8)]
            self.records.append(sFlowRecord(record_header, record_size, self.sampleType, record_data))
            data_position += record_size + 8


class sFlow:
    """sFlow class:

    agentAddress:  IP address of sampling agent sFlowAgentAddress.
    subAgent:  Used to distinguishing between datagram streams from separate agent sub entities within an device.
    sequenceNumber:  Incremented with each sample datagram generated by a sub-agent within an agent.
    sysUpTime:  Current time (in milliseconds since device last booted). Should be set as close to datagram transmission time as possible.
    samples:  A list of samples.

    """

    def __init__(self, datagram):

        self.len = len(datagram)
        self.data = datagram
        self.dgVersion = unpack(">i", datagram[0:4])[0]
        self.addressType = unpack(">i", datagram[4:8])[0]
        if self.addressType == 1:
            self.agentAddress = inet_ntop(AF_INET, datagram[8:12])
            self.subAgent = unpack(">i", datagram[12:16])[0]
            self.sequenceNumber = unpack(">i", datagram[16:20])[0]
            self.sysUpTime = unpack(">i", datagram[20:24])[0]
            self.NumberSample = unpack(">i", datagram[24:28])[0]
            data_position = 28
        elif self.addressType == 2:
            self.agentAddress = inet_ntop(AF_INET6, datagram[8:24])  # Temporary fix due to lack of IPv6 support on WIN32
            self.subAgent = unpack(">i", datagram[24:28])[0]
            self.sequenceNumber = unpack(">i", datagram[28:32])[0]
            self.sysUpTime = unpack(">i", datagram[32:36])[0]
            self.NumberSample = unpack(">i", datagram[36:40])[0]
            data_position = 40
        else:
            self.agentAddress = 0
            self.subAgent = 0
            self.sequenceNumber = 0
            self.sysUpTime = 0
            self.NumberSample = 0
        self.samples = []
        if self.NumberSample > 0:
            for _ in range(self.NumberSample):
                sample_header = datagram[(data_position) : (data_position + 4)]
                sample_size = unpack(">i", datagram[(data_position + 4) : (data_position + 8)])[0]
                sample_datagram = datagram[(data_position + 8) : (data_position + sample_size + 8)]

                self.samples.append(sFlowSample(sample_header, sample_size, sample_datagram))
                data_position = data_position + 8 + sample_size
