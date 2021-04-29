#!/usr/bin/python
from struct import unpack
from socket import inet_ntop, AF_INET, AF_INET6
from uuid import UUID


# The sFlow Collector is a class for parsing sFlow data.

# sFlow datagrams contain a header, which may contain samples which may contain records.
# The data_gram may not contain a sample, but if it does there will be at least on record.
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
    def __init__(self, length, data_gram):
        self.len = length
        self.data = data_gram

    def __repr__(self):
        return "sFlow Record Type Not Implimented."

    def __len__(self):
        return 1


# Flow Record Types


class sFlowRawPacketHeader:
    "flowData: enterprise = 0, format = 1"

    def __init__(self, length, data_gram):
        self.len = length
        self.data = data_gram
        self.headerProtocol = unpack(">i", data_gram[0:4])[0]
        self.frameLength = unpack(">i", data_gram[4:8])[0]
        self.payloadRemoved = unpack(">i", data_gram[8:12])[0]
        self.headerSize = unpack(">i", data_gram[12:16])[0]
        self.header = data_gram[(16) : (16 + self.headerSize)]
        ofset = 0
        self.type = unpack(">H", data_gram[36:38])[0]
        if self.type == int(16384):  # if 802.1q info in sample header
            ofset = 4
        self.srcMAC = data_gram[22:28].hex("-")
        self.dstMAC = data_gram[16:22].hex("-")
        self.srcIp = inet_ntop(AF_INET, data_gram[46 - ofset : 50 - ofset])
        self.dstIp = inet_ntop(AF_INET, data_gram[50 - ofset : 54 - ofset])
        self.srcPort = unpack(">H", data_gram[54 - ofset : 56 - ofset])[0]
        self.dstPort = unpack(">H", data_gram[56 - ofset : 58 - ofset])[0]

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

    def __init__(self, length, data_gram):
        self.len = length
        self.data = data_gram
        self.frameLength = unpack(">i", data_gram[0:4])[0]
        self.srcMAC = data_gram[4:10].hex("-")
        self.dstMAC = data_gram[12:18].hex("-")
        self.type = unpack(">i", data_gram[20:24])[0]

    def __repr__(self):
        return f"""
            Ethernet Frame:
                Source MAC: {self.srcMAC}
                Destination MAC: {self.dstMAC}
                Frame Type: {self.type}
        """


class sFlowSampledIpv4:
    "flowData: enterprise = 0, format = 3"

    def __init__(self, length, data_gram):
        self.len = length
        self.data = data_gram
        self.length = unpack(">i", data_gram[0:4])[0]
        self.protocol = unpack(">i", data_gram[4:8])[0]
        self.srcIp = inet_ntop(AF_INET, data_gram[8:12])
        self.dstIp = inet_ntop(AF_INET, data_gram[12:16])
        self.srcPort = unpack(">i", data_gram[16:20])[0]
        self.dstPort = unpack(">i", data_gram[20:24])[0]
        self.tcpFlags = unpack(">i", data_gram[24:28])[0]
        self.tos = unpack(">i", data_gram[28:32])[0]

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

    def __init__(self, length, data_gram):
        self.len = length
        self.data = data_gram
        self.length = unpack(">i", data_gram[0:4])[0]
        self.protocol = unpack(">i", data_gram[4:8])[0]
        self.srcIp = inet_ntop(AF_INET6, data_gram[8:24])
        self.dstIp = inet_ntop(AF_INET6, data_gram[24:40])
        self.srcPort = unpack(">i", data_gram[40:44])[0]
        self.dstPort = unpack(">i", data_gram[44:48])[0]
        self.tcpFlags = unpack(">i", data_gram[48:52])[0]
        self.priority = unpack(">i", data_gram[52:56])[0]

    def __repr__(self):
        return f"""
            IPv6 Sample:
                Length: {self.len}
        """


class sFlowExtendedSwitch:
    "flowData: enterprise = 0, format = 1001"

    def __init__(self, length, data_gram):
        self.len = length
        self.data = data_gram
        self.srcVLAN = unpack(">i", data_gram[0:4])[0]
        self.srcPriority = unpack(">i", data_gram[4:8])[0]
        self.dstVLAN = unpack(">i", data_gram[8:12])[0]
        self.dstPriority = unpack(">i", data_gram[12:16])[0]

    def __repr__(self):
        return f"""
            Extended Switch:
                Length: {self.len}
        """


class sFlowExtendedRouter:
    "flowData: enterprise = 0, format = 1002"

    def __init__(self, length, data_gram):
        self.len = length
        self.data = data_gram
        self.addressType = unpack(">i", data_gram[0:4])[0]
        if self.addressType == 1:
            self.nextHop = inet_ntop(AF_INET, data_gram[4:8])
            dataPosition = 8
        elif self.addressType == 2:
            self.nextHop = inet_ntop(AF_INET6, data_gram[4:20])
            dataPosition = 20
        else:
            self.nextHop = 0
            self.srcMaskLen = 0
            self.dstMaskLen = 0
            return
        self.srcMaskLen = unpack(">i", data_gram[dataPosition : (dataPosition + 4)])[0]
        dataPosition += 4
        self.dstMaskLen = unpack(">i", data_gram[dataPosition : (dataPosition + 4)])[0]

    def __repr__(self):
        return f"""
            Extended Router:
                Length: {self.len}
        """


class sFlowExtendedGateway:
    "flowData: enterprise = 0, format = 1003"

    def __init__(self, length, data_gram):
        self.len = length
        self.data = data_gram
        self.addressType = unpack(">i", data_gram[0:4])[0]
        if self.addressType == 1:
            self.nextHop = inet_ntop(AF_INET, data_gram[4:8])
            dataPosition = 8
        elif self.addressType == 2:
            self.nextHop = inet_ntop(AF_INET6, data_gram[4:20])
            dataPosition = 20
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
        self.asNumber = unpack(">i", data_gram[dataPosition : (dataPosition + 4)])[0]
        dataPosition += 4
        self.srcAsNumber = unpack(">i", data_gram[dataPosition : (dataPosition + 4)])[0]
        dataPosition += 4
        self.srcPeerAsNumber = unpack(">i", data_gram[dataPosition : (dataPosition + 4)])[0]
        dataPosition += 4
        self.asPathType = unpack(">i", data_gram[dataPosition : (dataPosition + 4)])[0]
        dataPosition += 4
        self.asPathCount = unpack(">i", data_gram[dataPosition : (dataPosition + 4)])[0]
        dataPosition += 4
        self.dstAsPath = unpack(f'>{"i" * self.asPathCount}', data_gram[dataPosition : (dataPosition + self.asPathCount * 4)])
        dataPosition += self.asPathCount * 4
        self.communitiesCount = unpack(">i", data_gram[dataPosition : (dataPosition + 4)])[0]
        dataPosition += 4
        self.communities = unpack(
            f'>{"i" * self.communitiesCount}', data_gram[dataPosition : (dataPosition + self.communitiesCount * 4)]
        )
        dataPosition += self.communitiesCount * 4
        self.localpref = unpack(">i", data_gram[dataPosition : (dataPosition + 4)])[0]

    def __repr__(self):
        return f"""
            Extended Gateway:
                Length: {self.len}
        """


class sFlowExtendedUser:
    "flowData: enterprise = 0, format = 1004"

    def __init__(self, length, data_gram):
        self.len = length
        self.data = data_gram
        self.srcCharset = unpack(">i", data_gram[0:4])
        nameLength = unpack(">i", data_gram[4:8])[0]
        self.srcUser = data_gram[8 : (8 + nameLength)].decode("utf-8")
        dataPosition = nameLength + (4 - nameLength) % 4
        self.dstCharset = data_gram[dataPosition : (dataPosition + nameLength)].decode("utf-8")
        dataPosition += 4
        nameLength = unpack(">i", data_gram[4:8])[0]
        self.dstUser = data_gram[dataPosition : (dataPosition + nameLength)].decode("utf-8")

    def __repr__(self):
        return f"""
            Extended User:
                Length: {self.len}
        """


class sFlowExtendedUrl:
    "flowData: enterprise = 0, format = 1005"

    def __init__(self, length, data_gram):
        self.len = length
        self.data = data_gram
        self.direction = unpack(">i", data_gram[0:4])[0]
        nameLength = min(unpack(">i", data_gram[4:8])[0], 255)
        dataPosition = 8
        self.url = data_gram[dataPosition : (dataPosition + nameLength)].decode("utf-8")
        dataPosition += nameLength + (4 - nameLength) % 4
        nameLength = min(unpack(">i", data_gram[dataPosition : (dataPosition + 4)])[0], 255)
        dataPosition += 4
        self.host = data_gram[dataPosition : (dataPosition + nameLength)].decode("utf-8")
        nameLength = unpack(">i", data_gram[0:4])[0]
        self.PortName = data_gram[dataPosition : (dataPosition + nameLength)].decode("utf-8")

    def __repr__(self):
        return f"""
            Extended URL:
                Length: {self.len}
        """


class sFlowExtendedMpls:
    "flowData: enterprise = 0, format = 1006"

    def __init__(self, length, data_gram):
        self.len = length
        self.data = data_gram
        self.addressType = unpack(">i", data_gram[0:4])[0]
        dataPosition = 4
        if self.addressType == 1:
            self.nextHop = inet_ntop(AF_INET, data_gram[dataPosition : (dataPosition + 4)])
            dataPosition += 4
        elif self.addressType == 2:
            self.nextHop = inet_ntop(AF_INET6, data_gram[dataPosition : (dataPosition + 16)])
            dataPosition += 16
        else:
            self.nextHop = 0
            self.inLabelStackCount = 0
            self.inLabelStack = []
            self.outLabelStackCount = 0
            self.outLabelStack = []
            return
        self.inLabelStackCount = unpack(">i", data_gram[dataPosition : (dataPosition + 4)])[0]
        dataPosition += 4
        self.inLabelStack = unpack(
            f'>{"i" * self.inLabelStackCount}', data_gram[dataPosition : (dataPosition + self.inLabelStackCount * 4)]
        )
        dataPosition += self.inLabelStackCount * 4
        self.outLabelStackCount = unpack(">i", data_gram[dataPosition : (dataPosition + 4)])[0]
        dataPosition += 4
        self.outLabelStack = unpack(
            f'>{"i" * self.outLabelStackCount}', data_gram[dataPosition : (dataPosition + self.outLabelStackCount * 4)]
        )

    def __repr__(self):
        return f"""
            Extended MPLS:
                Length: {self.len}
        """


class sFlowExtendedNat:
    "flowData: enterprise = 0, format = 1007"

    def __init__(self, length, data_gram):
        self.len = length
        self.data = data_gram
        self.srcAddressType = unpack(">i", data_gram[0:4])[0]
        dataPosition = 4
        if self.srcAddressType == 1:
            self.srcAddress = inet_ntop(AF_INET, data_gram[dataPosition : (dataPosition + 4)])
            dataPosition += 4
        elif self.srcAddressType == 2:
            self.srcAddress = inet_ntop(AF_INET6, data_gram[dataPosition : (dataPosition + 16)])
            dataPosition += 16
        else:
            self.srcAddress = 0
            self.dstAddress = 0
            return
        self.dstAddressType = unpack(">i", data_gram[0:4])[0]
        dataPosition += 4
        if self.dstAddressType == 1:
            self.dstAddress = inet_ntop(AF_INET, data_gram[dataPosition : (dataPosition + 4)])
            dataPosition += 4
        elif self.dstAddressType == 2:
            self.dstAddress = inet_ntop(AF_INET6, data_gram[dataPosition : (dataPosition + 16)])
            dataPosition += 16
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

    def __init__(self, length, data_gram):
        self.len = length
        self.data = data_gram
        nameLength = min(unpack(">i", data_gram[0:4])[0], 255)
        self.host = data_gram[4 : (4 + nameLength)].decode("utf-8")
        dataPosition = 4 + nameLength + (4 - nameLength) % 4
        self.tunnelId = unpack(">i", data_gram[dataPosition : (dataPosition + 4)])[0]
        dataPosition += 4
        self.tunnelCos = unpack(">i", data_gram[dataPosition : (dataPosition + 4)])[0]

    def __repr__(self):
        return f"""
            Extended MPLS Tunnel:
                Length: {self.len}
        """


class sFlowExtendedMplsVc:
    "flowData: enterprise = 0, format = 1009"

    def __init__(self, length, data_gram):
        self.len = length
        self.data = data_gram
        nameLength = min(unpack(">i", data_gram[0:4])[0], 255)
        self.vcInstanceName = data_gram[4 : (4 + nameLength)].decode("utf-8")
        dataPosition = 4 + nameLength + (4 - nameLength) % 4
        self.vllVcId = unpack(">i", data_gram[dataPosition : (dataPosition + 4)])[0]
        dataPosition += 4
        self.vcLabelCos = unpack(">i", data_gram[dataPosition : (dataPosition + 4)])[0]

    def __repr__(self):
        return f"""
            Extended MPLS Virtual Circuit:
                Length: {self.len}
        """


class sFlowExtendedMpls_FTN:
    "flowData: enterprise = 0, format = 1010"

    def __init__(self, length, data_gram):
        self.len = length
        self.data = data_gram
        nameLength = min(unpack(">i", data_gram[0:4])[0], 255)
        self.mplsFTNDescr = data_gram[4 : (4 + nameLength)].decode("utf-8")
        dataPosition = 4 + nameLength + (4 - nameLength) % 4
        self.mplsFTNMask = unpack(">i", data_gram[dataPosition : (dataPosition + 4)])[0]

    def __repr__(self):
        return f"""
            Extended MPLS FTN:
                Length: {self.len}
        """


class sFlowExtendedMpls_LDP_FEC:
    "flowData: enterprise = 0, format = 1011"

    def __init__(self, length, data_gram):
        self.len = length
        self.data = data_gram
        self.mplsFecAddrPrefixLength = unpack(">i", data_gram)[0]

    def __repr__(self):
        return f"""
            Extended MPLS LDP FEC:
                Length: {self.len}
        """


class sFlowExtendedVlantunnel:
    "flowData: enterprise = 0, format = 1012"

    def __init__(self, length, data_gram):
        self.len = length
        self.data = data_gram
        stackCount = unpack(">i", data_gram[0:4])[0]
        self.stack = unpack(f'>{"i" * stackCount}', data_gram[4 : (4 + stackCount * 4)])

    def __repr__(self):
        return f"""
            Extended VLAN Tunnel:
                Length: {self.len}
        """


class sFlowExtendedSocketIpv4:
    "flowData: enterprise = 0, format = 2100"

    def __init__(self, length, data_gram):
        self.len = length
        self.data = data_gram
        self.protocol = unpack(">i", data_gram[0:4])[0]
        self.localIp = inet_ntop(AF_INET, data_gram[4:8])
        self.remoteIp = inet_ntop(AF_INET, data_gram[8:12])
        self.localPort = unpack(">i", data_gram[12:16])[0]
        self.remotePort = unpack(">i", data_gram[16:20])[0]

    def __repr__(self):
        return f"""
            Extended IPv4 Socket:
                Length: {self.len}
        """


class sFlowExtendedSocketIpv6:
    "flowData: enterprise = 0, format = 2101"

    def __init__(self, length, data_gram):
        self.len = length
        self.data = data_gram
        self.protocol = unpack(">i", data_gram[0:4])[0]
        self.localIp = inet_ntop(AF_INET6, data_gram[4:20])
        self.remoteIp = inet_ntop(AF_INET6, data_gram[20:36])
        self.localPort = unpack(">i", data_gram[36:40])[0]
        self.remotePort = unpack(">i", data_gram[40:44])[0]

    def __repr__(self):
        return f"""
            Extended IPv6 Socket:
                Length: {self.len}
        """


# Counter Record Types


class sFlowIfCounters:
    "counterData: enterprise = 0, format = 1"

    def __init__(self, length, data_gram):
        self.len = length
        self.data = data_gram
        self.index = unpack(">i", data_gram[0:4])[0]
        self.type = unpack(">i", data_gram[4:8])[0]
        self.speed = unpack(">q", data_gram[8:16])[0]  # 64-bit
        self.direction = unpack(">i", data_gram[16:20])[0]
        self.status = unpack(">i", data_gram[20:24])[0]  # This is really a 2-bit value
        self.inputOctets = unpack(">q", data_gram[24:32])[0]  # 64-bit
        self.inputPackets = unpack(">i", data_gram[32:36])[0]
        self.inputMulticast = unpack(">i", data_gram[36:40])[0]
        self.inputBroadcast = unpack(">i", data_gram[40:44])[0]
        self.inputDiscarded = unpack(">i", data_gram[44:48])[0]
        self.inputErrors = unpack(">i", data_gram[48:52])[0]
        self.inputUnknown = unpack(">i", data_gram[52:56])[0]
        self.outputOctets = unpack(">q", data_gram[56:64])[0]  # 64-bit
        self.outputPackets = unpack(">i", data_gram[64:68])[0]
        self.outputMulticast = unpack(">i", data_gram[68:72])[0]
        self.outputBroadcast = unpack(">i", data_gram[72:76])[0]
        self.outputDiscarded = unpack(">i", data_gram[76:80])[0]
        self.outputErrors = unpack(">i", data_gram[80:84])[0]
        self.promiscuous = unpack(">i", data_gram[84:88])[0]

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

    def __init__(self, length, data_gram):
        self.len = length
        self.data = data_gram
        self.alignmentError = unpack(">i", data_gram[0:4])[0]
        self.fcsError = unpack(">i", data_gram[4:8])[0]
        self.singleCollision = unpack(">i", data_gram[8:12])[0]
        self.multipleCollision = unpack(">i", data_gram[12:16])[0]
        self.sqeTest = unpack(">i", data_gram[16:20])[0]
        self.deferred = unpack(">i", data_gram[20:24])[0]
        self.lateCollision = unpack(">i", data_gram[24:28])[0]
        self.excessiveCollision = unpack(">i", data_gram[28:32])[0]
        self.internalTransmitError = unpack(">i", data_gram[32:36])[0]
        self.carrierSenseError = unpack(">i", data_gram[36:40])[0]
        self.frameTooLong = unpack(">i", data_gram[40:44])[0]
        self.internalReceiveError = unpack(">i", data_gram[44:48])[0]
        self.symbolError = unpack(">i", data_gram[48:52])[0]

    def __repr__(self):
        return f"""
            Ethernet Counters:
                Length: {self.len}
        """


class sFlowTokenringCounters:
    "counterData: enterprise = 0, format = 3"

    def __init__(self, length, data_gram):
        self.len = length
        self.data = data_gram
        self.dot5StatsLineErrors = unpack(">i", data_gram[0:4])[0]
        self.dot5StatsBurstErrors = unpack(">i", data_gram[4:8])[0]
        self.dot5StatsACErrors = unpack(">i", data_gram[8:12])[0]
        self.dot5StatsAbortTransErrors = unpack(">i", data_gram[12:16])[0]
        self.dot5StatsInternalErrors = unpack(">i", data_gram[16:20])[0]
        self.dot5StatsLostFrameErrors = unpack(">i", data_gram[20:24])[0]
        self.dot5StatsReceiveCongestions = unpack(">i", data_gram[24:28])[0]
        self.dot5StatsFrameCopiedErrors = unpack(">i", data_gram[28:32])[0]
        self.dot5StatsTokenErrors = unpack(">i", data_gram[32:36])[0]
        self.dot5StatsSoftErrors = unpack(">i", data_gram[36:40])[0]
        self.dot5StatsHardErrors = unpack(">i", data_gram[40:44])[0]
        self.dot5StatsSignalLoss = unpack(">i", data_gram[44:48])[0]
        self.dot5StatsTransmitBeacons = unpack(">i", data_gram[48:52])[0]
        self.dot5StatsRecoverys = unpack(">i", data_gram[52:56])[0]
        self.dot5StatsLobeWires = unpack(">i", data_gram[56:60])[0]
        self.dot5StatsRemoves = unpack(">i", data_gram[60:64])[0]
        self.dot5StatsSingles = unpack(">i", data_gram[64:68])[0]
        self.dot5StatsFreqErrors = unpack(">i", data_gram[68:72])[0]

    def __repr__(self):
        return f"""
            Token Ring Counters:
                Length: {self.len}
        """


class sFlowVgCounters:
    "counterData: enterprise = 0, format = 4"

    def __init__(self, length, data_gram):
        self.len = length
        self.data = data_gram
        self.dot12InHighPriorityFrames = unpack(">i", data_gram[0:4])[0]
        self.dot12InHighPriorityOctets = unpack(">q", data_gram[4:12])[0]
        self.dot12InNormPriorityFrames = unpack(">i", data_gram[12:16])[0]
        self.dot12InNormPriorityOctets = unpack(">q", data_gram[16:24])[0]
        self.dot12InIPMErrors = unpack(">i", data_gram[24:28])[0]
        self.dot12InOversizeFrameErrors = unpack(">i", data_gram[28:32])[0]
        self.dot12InDataErrors = unpack(">i", data_gram[32:36])[0]
        self.dot12InNullAddressedFrames = unpack(">i", data_gram[36:40])[0]
        self.dot12OutHighPriorityFrames = unpack(">i", data_gram[40:44])[0]
        self.dot12OutHighPriorityOctets = unpack(">q", data_gram[44:52])[0]
        self.dot12TransitionIntoTrainings = unpack(">i", data_gram[52:56])[0]
        self.dot12HCInHighPriorityOctets = unpack(">q", data_gram[56:64])[0]
        self.dot12HCInNormPriorityOctets = unpack(">q", data_gram[64:72])[0]
        self.dot12HCOutHighPriorityOctets = unpack(">q", data_gram[72:80])[0]

    def __repr__(self):
        return f"""
            VG Counters:
                Length: {self.len}
        """


class sFlowVLAN:
    "counterData: enterprise = 0, format = 5"

    def __init__(self, length, data_gram):
        self.len = length
        self.data = data_gram
        self.vlanID = unpack(">i", data_gram[0:4])[0]
        self.octets = unpack(">q", data_gram[4:12])[0]  # 64-bit
        self.unicast = unpack(">i", data_gram[12:16])[0]
        self.multicast = unpack(">i", data_gram[16:20])[0]
        self.broadcast = unpack(">i", data_gram[20:24])[0]
        self.discard = unpack(">i", data_gram[24:28])[0]

    def __repr__(self):
        return f"""
            VLAN Counters:
                Length: {self.len}
        """


class sFlowProcessor:
    "counterData: enterprise = 0, format = 1001"

    def __init__(self, length, data_gram):
        self.len = length
        self.data = data_gram
        self.cpu5s = unpack(">i", data_gram[0:4])[0]
        self.cpu1m = unpack(">i", data_gram[4:8])[0]
        self.cpu5m = unpack(">i", data_gram[8:12])[0]
        self.totalMemory = unpack(">q", data_gram[12:20])[0]  # 64-bit
        self.freeMemory = unpack(">q", data_gram[20:28])[0]  # 64-bit

    def __repr__(self):
        return f"""
            Processor Counters:
                Length: {self.len}
        """


class sFlowOfPort:
    "counterData: enterprise = 0, format = 1004"

    def __init__(self, length, data_gram):
        self.len = length
        self.data = data_gram
        self.datapathId = unpack(">i", data_gram[0:8])[0]
        self.portNo = unpack(">i", data_gram[8:12])[0]

    def __repr__(self):
        return f"""
            OpenFlow Port:
                Length: {self.len}
        """


class sFlowPortName:
    "counterData: enterprise = 0, format = 1005"

    def __init__(self, length, data_gram):
        self.len = length
        self.data = data_gram
        nameLength = unpack(">i", data_gram[0:4])[0]
        self.PortName = data_gram[4 : (4 + nameLength)].decode("utf-8")

    def __repr__(self):
        return f"""
            OpenFlow Port Name:
                Length: {self.len}
        """


class sFlowHostDescr:
    "counterData: enterprise = 0, format = 2000"

    def __init__(self, length, data_gram):
        self.len = length
        self.data = data_gram
        nameLength = min(unpack(">i", data_gram[0:4])[0], 64)
        dataPosition = 4
        self.hostname = data_gram[dataPosition : (dataPosition + nameLength)].decode("utf-8")
        dataPosition += nameLength + (4 - nameLength) % 4
        self.uuid = UUID(bytes=data_gram[dataPosition : (dataPosition + 16)])
        dataPosition = dataPosition + 16
        self.machineType = unpack(">i", data_gram[dataPosition : (dataPosition + 4)])[0]
        dataPosition = dataPosition + 4
        self.osName = unpack(">i", data_gram[dataPosition : (dataPosition + 4)])[0]
        dataPosition = dataPosition + 4
        nameLength = min(unpack(">i", data_gram[dataPosition : (dataPosition + 4)])[0], 32)
        dataPosition += 4
        self.osRelease = data_gram[dataPosition : (dataPosition + nameLength)].decode("utf-8")

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

    def __init__(self, length, data_gram):
        self.len = length
        self.data = data_gram
        self.adapters = []
        hostAdapterCount = unpack(">i", data_gram[0:4])[0]
        dataPosition = 4
        for _ in range(hostAdapterCount):
            hostadapter = self.hostAdapter()
            hostadapter.ifIndex = unpack(">i", data_gram[dataPosition : (dataPosition + 4)])[0]
            dataPosition += 4
            hostadapter.macAddressCount = unpack(">i", data_gram[dataPosition : (dataPosition + 4)])[0]
            dataPosition += 4
            hostadapter.macAddresses = []
            for macNum in range(hostadapter.macAddressCount):
                hostadapter.macAddresses.append(data_gram[(dataPosition + macNum * 8) : (dataPosition + macNum * 8 + 6)]).hex("-")
            dataPosition += hostadapter.macAddressCount * 8
            self.adapters.append(hostadapter)

    def __repr__(self):
        return f"""
            Host Adapters:
                Length: {self.len}
        """


class sFlowHostParent:
    "counterData: enterprise = 0, format = 2002"

    def __init__(self, length, data_gram):
        self.len = length
        self.data = data_gram
        self.containerType = unpack(">i", data_gram[0:4])[0]
        self.containerIndex = unpack(">i", data_gram[4:8])[0]

    def __repr__(self):
        return f"""
            Host Parent:
                Length: {self.len}
        """


class sFlowHostCPU:
    "counterData: enterprise = 0, format = 2003"

    def __init__(self, length, data_gram):
        self.len = length
        self.data = data_gram
        self.avgLoad1 = unpack(">f", data_gram[0:4])[0]  # Floating Point
        self.avgLoad5 = unpack(">f", data_gram[4:8])[0]  # Floating Point
        self.avgLoad15 = unpack(">f", data_gram[8:12])[0]  # Floating Point
        self.runProcess = unpack(">i", data_gram[12:16])[0]
        self.totalProcess = unpack(">i", data_gram[16:20])[0]
        self.numCPU = unpack(">i", data_gram[20:24])[0]
        self.mhz = unpack(">i", data_gram[24:28])[0]
        self.uptime = unpack(">i", data_gram[28:32])[0]
        self.timeUser = unpack(">i", data_gram[32:36])[0]
        self.timeNices = unpack(">i", data_gram[36:40])[0]
        self.timeKennal = unpack(">i", data_gram[40:44])[0]
        self.timeIdle = unpack(">i", data_gram[44:48])[0]
        self.timeIO = unpack(">i", data_gram[48:52])[0]
        self.timeInterrupt = unpack(">i", data_gram[52:56])[0]
        self.timeSoftInterrupt = unpack(">i", data_gram[56:60])[0]
        self.interrupt = unpack(">i", data_gram[60:64])[0]
        self.contextSwitch = unpack(">i", data_gram[64:68])[0]
        self.virtualInstance = unpack(">i", data_gram[68:72])[0]
        self.guestOS = unpack(">i", data_gram[72:76])[0]
        self.guestNice = unpack(">i", data_gram[76:80])[0]

    def __repr__(self):
        return f"""
            Host CPU Counters:
                Length: {self.len}
        """


class sFlowHostMemory:
    "counterData: enterprise = 0, format = 2004"

    def __init__(self, length, data_gram):
        self.len = length
        self.data = data_gram
        self.memTotal = unpack(">q", data_gram[0:8])[0]  # 64-bit
        self.memFree = unpack(">q", data_gram[8:16])[0]  # 64-bit
        self.memShared = unpack(">q", data_gram[16:24])[0]  # 64-bit
        self.memBuffers = unpack(">q", data_gram[24:32])[0]  # 64-bit
        self.memCache = unpack(">q", data_gram[32:40])[0]  # 64-bit
        self.swapTotal = unpack(">q", data_gram[40:48])[0]  # 64-bit
        self.swapFree = unpack(">q", data_gram[48:56])[0]  # 64-bit
        self.pageIn = unpack(">i", data_gram[56:60])[0]
        self.pageOut = unpack(">i", data_gram[60:64])[0]
        self.swapIn = unpack(">i", data_gram[64:68])[0]
        self.swapOut = unpack(">i", data_gram[68:72])[0]

    def __repr__(self):
        return f"""
            Host Memory Counters:
                Length: {self.len}
        """


class sFlowHostDiskIO:
    "counterData: enterprise = 0, format = 2005"

    def __init__(self, length, data_gram):
        self.len = length
        self.data = data_gram
        self.diskTotal = unpack(">q", data_gram[0:8])[0]  # 64-bit
        self.diskFree = unpack(">q", data_gram[8:16])[0]  # 64-bit
        self.partMaxused = (unpack(">i", data_gram[16:20])[0]) / float(100)
        self.read = unpack(">i", data_gram[20:24])[0]
        self.readByte = unpack(">q", data_gram[24:32])[0]  # 64-bit
        self.readTime = unpack(">i", data_gram[32:36])[0]
        self.write = unpack(">i", data_gram[36:40])[0]
        self.writeByte = unpack(">q", data_gram[40:48])[0]  # 64-bit
        self.writeTime = unpack(">i", data_gram[48:52])[0]

    def __repr__(self):
        return f"""
            Host Disk I/O Counters:
                Length: {self.len}
        """


class sFlowHostNetIO:
    "counterData: enterprise = 0, format = 2006"

    def __init__(self, length, data_gram):
        self.len = length
        self.data = data_gram
        self.inByte = unpack(">q", data_gram[0:8])[0]  # 64-bit
        self.inPacket = unpack(">i", data_gram[8:12])[0]
        self.inError = unpack(">i", data_gram[12:16])[0]
        self.inDrop = unpack(">i", data_gram[16:20])[0]
        self.outByte = unpack(">q", data_gram[20:28])[0]  # 64-bit
        self.outPacket = unpack(">i", data_gram[28:32])[0]
        self.outError = unpack(">i", data_gram[32:36])[0]
        self.outDrop = unpack(">i", data_gram[36:40])[0]

    def __repr__(self):
        return f"""
            Host Network I/O Counters:
                Length: {self.len}
        """


class sFlowMib2IP:
    "counterData: enterprise = 0, format = 2007"

    def __init__(self, length, data_gram):
        self.len = length
        self.data = data_gram
        self.forwarding = unpack(">i", data_gram[0:4])[0]
        self.defaultTTL = unpack(">i", data_gram[4:8])[0]
        self.inReceives = unpack(">i", data_gram[8:12])[0]
        self.inHeaderErrors = unpack(">i", data_gram[12:16])[0]
        self.inAddressErrors = unpack(">i", data_gram[16:20])[0]
        self.inForwardDatagrams = unpack(">i", data_gram[20:24])[0]
        self.inUnknownProtocols = unpack(">i", data_gram[24:28])[0]
        self.inDiscards = unpack(">i", data_gram[28:32])[0]
        self.inDelivers = unpack(">i", data_gram[32:36])[0]
        self.outRequests = unpack(">i", data_gram[36:40])[0]
        self.outDiscards = unpack(">i", data_gram[40:44])[0]
        self.outNoRoutes = unpack(">i", data_gram[44:48])[0]
        self.reassemblyTimeout = unpack(">i", data_gram[48:52])[0]
        self.reassemblyRequired = unpack(">i", data_gram[52:56])[0]
        self.reassemblyOkay = unpack(">i", data_gram[56:60])[0]
        self.reassemblyFail = unpack(">i", data_gram[60:64])[0]
        self.fragmentOkay = unpack(">i", data_gram[64:68])[0]
        self.fragmentFail = unpack(">i", data_gram[68:72])[0]
        self.fragmentCreate = unpack(">i", data_gram[72:76])[0]

    def __repr__(self):
        return f"""
            MIB2 IP Counters:
                Length: {self.len}
        """


class sFlowMib2ICMP:
    "counterData: enterprise = 0, format = 2008"

    def __init__(self, length, data_gram):
        self.len = length
        self.data = data_gram
        self.inMessage = unpack(">i", data_gram[0:4])[0]
        self.inError = unpack(">i", data_gram[4:8])[0]
        self.inDestinationUnreachable = unpack(">i", data_gram[8:12])[0]
        self.inTimeExceeded = unpack(">i", data_gram[12:16])[0]
        self.inParameterProblem = unpack(">i", data_gram[16:20])[0]
        self.inSourceQuence = unpack(">i", data_gram[20:24])[0]
        self.inRedirect = unpack(">i", data_gram[24:28])[0]
        self.inEcho = unpack(">i", data_gram[28:32])[0]
        self.inEchoReply = unpack(">i", data_gram[32:36])[0]
        self.inTimestamp = unpack(">i", data_gram[36:40])[0]
        self.inAddressMask = unpack(">i", data_gram[40:44])[0]
        self.inAddressMaskReply = unpack(">i", data_gram[44:48])[0]
        self.outMessage = unpack(">i", data_gram[48:52])[0]
        self.outError = unpack(">i", data_gram[52:56])[0]
        self.outDestinationUnreachable = unpack(">i", data_gram[56:60])[0]
        self.outTimeExceeded = unpack(">i", data_gram[60:64])[0]
        self.outParameterProblem = unpack(">i", data_gram[64:68])[0]
        self.outSourceQuence = unpack(">i", data_gram[68:72])[0]
        self.outRedirect = unpack(">i", data_gram[72:76])[0]
        self.outEcho = unpack(">i", data_gram[76:80])[0]
        self.outEchoReply = unpack(">i", data_gram[80:84])[0]
        self.outTimestamp = unpack(">i", data_gram[84:88])[0]
        self.outTimestampReply = unpack(">i", data_gram[88:92])[0]
        self.outAddressMask = unpack(">i", data_gram[92:96])[0]
        self.outAddressMaskReplay = unpack(">i", data_gram[96:100])[0]

    def __repr__(self):
        return f"""
            MIB2 ICMP Counters:
                Length: {self.len}
        """


class sFlowMib2TCP:
    "counterData: enterprise = 0, format = 2009"

    def __init__(self, length, data_gram):
        self.len = length
        self.data = data_gram
        self.algorithm = unpack(">i", data_gram[0:4])[0]
        self.rtoMin = unpack(">i", data_gram[4:8])[0]
        self.rtoMax = unpack(">i", data_gram[8:12])[0]
        self.maxConnection = unpack(">i", data_gram[12:16])[0]
        self.activeOpen = unpack(">i", data_gram[16:20])[0]
        self.passiveOpen = unpack(">i", data_gram[20:24])[0]
        self.attemptFail = unpack(">i", data_gram[24:28])[0]
        self.establishedReset = unpack(">i", data_gram[28:32])[0]
        self.currentEstablished = unpack(">i", data_gram[32:36])[0]
        self.inSegment = unpack(">i", data_gram[36:40])[0]
        self.outSegment = unpack(">i", data_gram[40:44])[0]
        self.retransmitSegment = unpack(">i", data_gram[44:48])[0]
        self.inError = unpack(">i", data_gram[48:52])[0]
        self.outReset = unpack(">i", data_gram[52:56])[0]
        self.inCsumError = unpack(">i", data_gram[56:60])[0]

    def __repr__(self):
        return f"""
            MIB2 TCP Counters:
                Length: {self.len}
        """


class sFlowMib2UDP:
    "counterData: enterprise = 0, format = 2010"

    def __init__(self, length, data_gram):
        self.len = length
        self.data = data_gram
        self.inDatagrams = unpack(">i", data_gram[0:4])[0]
        self.noPorts = unpack(">i", data_gram[4:8])[0]
        self.inErrors = unpack(">i", data_gram[8:12])[0]
        self.outDatagrams = unpack(">i", data_gram[12:16])[0]
        self.receiveBufferError = unpack(">i", data_gram[16:20])[0]
        self.sendBufferError = unpack(">i", data_gram[20:24])[0]
        self.inCheckSumError = unpack(">i", data_gram[24:28])[0]

    def __repr__(self):
        return f"""
            MIB2 UDP Counters:
                Length: {self.len}
        """


class sFlowVirtNode:
    "counterData: enterprise = 0, format = 2100"

    def __init__(self, length, data_gram):
        self.len = length
        self.data = data_gram
        self.mhz = unpack(">i", data_gram[0:4])[0]
        self.cpus = unpack(">i", data_gram[4:8])[0]
        self.memory = unpack(">q", data_gram[8:16])[0]
        self.memoryFree = unpack(">q", data_gram[16:24])[0]
        self.numDomains = unpack(">i", data_gram[24:28])[0]

    def __repr__(self):
        return f"""
            Virtual Node Counters:
                Length: {self.len}
        """


class sFlowVirtCPU:
    "counterData: enterprise = 0, format = 2101"

    def __init__(self, length, data_gram):
        self.len = length
        self.data = data_gram
        self.state = unpack(">i", data_gram[0:4])[0]
        self.cpuTime = unpack(">i", data_gram[4:8])[0]
        self.nrVirtCpu = unpack(">i", data_gram[8:12])[0]

    def __repr__(self):
        return f"""
            Virtual CPU Counters:
                Length: {self.len}
        """


class sFlowVirtMemory:
    "counterData: enterprise = 0, format = 2102"

    def __init__(self, length, data_gram):
        self.len = length
        self.data = data_gram
        self.memory = unpack(">q", data_gram[0:8])[0]
        self.maxMemory = unpack(">q", data_gram[8:16])[0]

    def __repr__(self):
        return f"""
            Virtual Memory Counters:
                Length: {self.len}
        """


class sFlowVirtDiskIO:
    "counterData: enterprise = 0, format = 2103"

    def __init__(self, length, data_gram):
        self.len = length
        self.data = data_gram
        self.capacity = unpack(">q", data_gram[0:8])[0]
        self.allocation = unpack(">q", data_gram[8:16])[0]
        self.available = unpack(">q", data_gram[16:24])[0]
        self.rdReq = unpack(">i", data_gram[24:28])[0]
        self.rdBytes = unpack(">q", data_gram[28:36])[0]
        self.wrReq = unpack(">i", data_gram[36:40])[0]
        self.wrBytes = unpack(">q", data_gram[40:48])[0]
        self.errs = unpack(">i", data_gram[48:52])[0]

    def __repr__(self):
        return f"""
            Virtual Disk IO Counters:
                Length: {self.len}
        """


class sFlowVirtNetIO:
    "counterData: enterprise = 0, format = 2104"

    def __init__(self, length, data_gram):
        self.len = length
        self.data = data_gram
        self.rxBytes = unpack(">q", data_gram[0:8])[0]
        self.rxPackets = unpack(">i", data_gram[8:12])[0]
        self.rxErrs = unpack(">i", data_gram[12:16])[0]
        self.rxDrop = unpack(">i", data_gram[16:20])[0]
        self.txBytes = unpack(">q", data_gram[20:28])[0]
        self.txPackets = unpack(">i", data_gram[28:32])[0]
        self.txErrs = unpack(">i", data_gram[32:36])[0]
        self.txDrop = unpack(">i", data_gram[36:40])[0]

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

    def __init__(self, header, length, sampleType, data_gram):
        self.header = header
        self.enterprise, self.format = divmod(self.header, 4096)
        self.len = length
        self.sampleType = sampleType
        self.data_gram = data_gram
        self.data = s_flow_record_format.get((sampleType, self.enterprise, self.format), sFlowRecordBase)(length, data_gram)


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

    def __init__(self, header, sampleSize, data_gram):

        self.len = sampleSize
        self.data = data_gram

        SampleHeader = unpack(">i", header)[0]
        self.enterprise, self.sampleType = divmod(SampleHeader, 4096)
        # 0 sample_data / 1 flow_data (single) / 2 counter_data (single)
        #             / 3 flow_data (expanded) / 4 counter_data (expanded)

        self.sequence = unpack(">i", data_gram[0:4])[0]

        if self.sampleType in [1, 2]:
            SampleSource = unpack(">i", data_gram[4:8])[0]
            self.sourceType, self.sourceIndex = divmod(SampleSource, 16777216)
            dataPosition = 8
        elif self.sampleType in [3, 4]:
            self.sourceType, self.sourceIndex = unpack(">ii", data_gram[4:12])
            dataPosition = 12
        else:
            pass  # sampleTypeError
        self.records = []

        if self.sampleType in [1, 3]:  # Flow
            self.sampleRate, self.samplePool, self.droppedPackets = unpack(">iii", data_gram[dataPosition : (dataPosition + 12)])
            dataPosition += 12
            if self.sampleType == 1:
                inputInterface, outputInterface = unpack(">ii", data_gram[(dataPosition) : (dataPosition + 8)])
                dataPosition += 8
                self.inputIfFormat, self.inputIfValue = divmod(inputInterface, 1073741824)
                self.outputIfFormat, self.outputIfValue = divmod(outputInterface, 1073741824)
            elif self.sampleType == 3:
                self.inputIfFormat, self.inputIfValue, self.outputIfFormat, self.outputIfValue = unpack(
                    ">ii", data_gram[dataPosition : (dataPosition + 16)]
                )
                dataPosition += 16
            self.recordCount = unpack(">i", data_gram[dataPosition : dataPosition + 4])[0]
            dataPosition += 4

        elif self.sampleType in [2, 4]:  # Counters
            self.recordCount = unpack(">i", data_gram[dataPosition : (dataPosition + 4)])[0]
            dataPosition += 4
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
            recordHeader = unpack(">i", data_gram[(dataPosition) : (dataPosition + 4)])[0]
            recordSize = unpack(">i", data_gram[(dataPosition + 4) : (dataPosition + 8)])[0]
            recordData = data_gram[(dataPosition + 8) : (dataPosition + recordSize + 8)]
            self.records.append(sFlowRecord(recordHeader, recordSize, self.sampleType, recordData))
            dataPosition += recordSize + 8


class sFlow:
    """sFlow class:

    agentAddress:  IP address of sampling agent sFlowAgentAddress.
    subAgent:  Used to distinguishing between data_gram streams from separate agent sub entities within an device.
    sequenceNumber:  Incremented with each sample data_gram generated by a sub-agent within an agent.
    sysUpTime:  Current time (in milliseconds since device last booted). Should be set as close to data_gram transmission time as possible.
    samples:  A list of samples.

    """

    def __init__(self, data_gram):

        self.len = len(data_gram)
        self.data = data_gram
        self.dgVersion = unpack(">i", data_gram[0:4])[0]
        self.addressType = unpack(">i", data_gram[4:8])[0]
        if self.addressType == 1:
            self.agentAddress = inet_ntop(AF_INET, data_gram[8:12])
            self.subAgent = unpack(">i", data_gram[12:16])[0]
            self.sequenceNumber = unpack(">i", data_gram[16:20])[0]
            self.sysUpTime = unpack(">i", data_gram[20:24])[0]
            self.NumberSample = unpack(">i", data_gram[24:28])[0]
            dataPosition = 28
        elif self.addressType == 2:
            self.agentAddress = inet_ntop(AF_INET6, data_gram[8:24])  # Temporary fix due to lack of IPv6 support on WIN32
            self.subAgent = unpack(">i", data_gram[24:28])[0]
            self.sequenceNumber = unpack(">i", data_gram[28:32])[0]
            self.sysUpTime = unpack(">i", data_gram[32:36])[0]
            self.NumberSample = unpack(">i", data_gram[36:40])[0]
            dataPosition = 40
        else:
            self.agentAddress = 0
            self.subAgent = 0
            self.sequenceNumber = 0
            self.sysUpTime = 0
            self.NumberSample = 0
        self.samples = []
        if self.NumberSample > 0:
            for _ in range(self.NumberSample):
                sampleHeader = data_gram[(dataPosition) : (dataPosition + 4)]
                sampleSize = unpack(">i", data_gram[(dataPosition + 4) : (dataPosition + 8)])[0]
                sampleDataGram = data_gram[(dataPosition + 8) : (dataPosition + sampleSize + 8)]

                self.samples.append(sFlowSample(sampleHeader, sampleSize, sampleDataGram))
                dataPosition = dataPosition + 8 + sampleSize
