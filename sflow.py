from socket import AF_INET, AF_INET6, inet_ntop
from struct import unpack
from uuid import UUID

# The sFlow Collector is a class for parsing sFlow data.

# sFlow datagrams contain a header, which may contain samples which may contain records.
# The datagram may not contain a sample, but if it does there will be at least on record.
# The records may have different formats.

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
    def __init__(self, datagram):
        self.data = datagram

    def __repr__(self):
        return """
            sFlow Record Type Not Implimented:
                Incomplete
            """

    def __len__(self):
        return 1


# Flow Record Types


class sFlowRawPacketHeader:
    "flowData: enterprise = 0, format = 1"

    def __init__(self, datagram):
        self.header_protocol = unpack(">i", datagram[0:4])[0]
        self.frame_length = unpack(">i", datagram[4:8])[0]
        self.payload_removed = unpack(">i", datagram[8:12])[0]
        self.header_size = unpack(">i", datagram[12:16])[0]
        self.header = datagram[(16) : (16 + self.header_size)]
        offset = 0
        self.type = unpack(">H", datagram[36:38])[0]
        if self.type == int(16384):  # 802.1q info in sample header
            offset = 4
        self.source_mac = datagram[22:28].hex("-")
        self.destination_mac = datagram[16:22].hex("-")
        self.source_ip = inet_ntop(AF_INET, datagram[46 - offset : 50 - offset])
        self.destination_ip = inet_ntop(AF_INET, datagram[50 - offset : 54 - offset])
        self.source_port = unpack(">H", datagram[54 - offset : 56 - offset])[0]
        self.destination_port = unpack(">H", datagram[56 - offset : 58 - offset])[0]

    def __repr__(self):
        return f"""
            Raw Packet Header:
                Protocol: {self.header_protocol}
                Frame Length: {self.frame_length}
                Header Size: {self.header_size}
                Payload Removed: {self.payload_removed}
                Source MAC: {self.source_mac}
                Destination MAC: {self.destination_mac}
                Source IP: {self.source_ip}
                Destination IP: {self.destination_ip}
                Source Port: {self.source_port}
                Destination Port: {self.destination_port}
        """

    def __len__(self):
        return 1


class sFlowEthernetFrame:
    "flowData: enterprise = 0, format = 2"

    def __init__(self, datagram):
        self.frame_length = unpack(">i", datagram[0:4])[0]
        self.source_mac = datagram[4:10].hex("-")
        self.destination_mac = datagram[12:18].hex("-")
        self.type = unpack(">i", datagram[20:24])[0]

    def __repr__(self):
        return f"""
            Ethernet Frame:
                Frame Length: {self.frame_length}
                Source MAC: {self.source_mac}
                Destination MAC: {self.destination_mac}
                Frame Type: {self.type}
        """

    def __len__(self):
        return 1


class sFlowSampledIpv4:
    "flowData: enterprise = 0, format = 3"

    def __init__(self, datagram):
        self.length = unpack(">i", datagram[0:4])[0]
        self.protocol = unpack(">i", datagram[4:8])[0]
        self.source_ip = inet_ntop(AF_INET, datagram[8:12])
        self.destination_ip = inet_ntop(AF_INET, datagram[12:16])
        self.source_port = unpack(">i", datagram[16:20])[0]
        self.destination_port = unpack(">i", datagram[20:24])[0]
        self.tcp_flags = unpack(">i", datagram[24:28])[0]
        self.tos = unpack(">i", datagram[28:32])[0]

    def __repr__(self):
        return f"""
            IPv4 Sample:
                Protocol: {self.protocol}
                Source IP: {self.source_ip}
                Destination IP: {self.destination_ip}
                Source Port: {self.source_port}
                Destination Port: {self.destination_port}
                TCP Flags: {self.tcp_flags}
                Type of Service: {self.tos}
        """

    def __len__(self):
        return 1


class sFlowSampledIpv6:
    "flowData: enterprise = 0, format = 4"

    def __init__(self, datagram):
        self.length = unpack(">i", datagram[0:4])[0]
        self.protocol = unpack(">i", datagram[4:8])[0]
        self.source_ip = inet_ntop(AF_INET6, datagram[8:24])
        self.destination_ip = inet_ntop(AF_INET6, datagram[24:40])
        self.source_port = unpack(">i", datagram[40:44])[0]
        self.destination_port = unpack(">i", datagram[44:48])[0]
        self.tcp_flags = unpack(">i", datagram[48:52])[0]
        self.priority = unpack(">i", datagram[52:56])[0]

    def __repr__(self):
        return f"""
            IPv6 Sample:
                Protocol: {self.protocol}
                Source IP: {self.source_ip}
                Destination IP: {self.destination_ip}
                Source Port: {self.source_port}
                Destination Port: {self.destination_port}
                TCP Flags: {self.tcp_flags}
                Priority: {self.priority}
        """

    def __len__(self):
        return 1


class sFlowExtendedSwitch:
    "flowData: enterprise = 0, format = 1001"

    def __init__(self, datagram):
        self.source_vlan = unpack(">i", datagram[0:4])[0]
        self.source_priority = unpack(">i", datagram[4:8])[0]
        self.destination_vlan = unpack(">i", datagram[8:12])[0]
        self.destination_priority = unpack(">i", datagram[12:16])[0]

    def __repr__(self):
        return f"""
            Extended Switch:
                Source VLAN: {self.source_vlan}
                Source Priority: {self.source_priority}
                Destination VLAN: {self.destination_vlan}
                Destination Priority: {self.destination_priority}
        """

    def __len__(self):
        return 1


class sFlowExtendedRouter:
    "flowData: enterprise = 0, format = 1002"

    def __init__(self, datagram):
        self.address_type = unpack(">i", datagram[0:4])[0]
        if self.address_type == 1:
            self.next_hop = inet_ntop(AF_INET, datagram[4:8])
            data_position = 8
        elif self.address_type == 2:
            self.next_hop = inet_ntop(AF_INET6, datagram[4:20])
            data_position = 20
        else:
            self.next_hop = 0
            self.source_mask_length = 0
            self.destination_mask_length = 0
            return
        self.source_mask_length = unpack(">i", datagram[data_position : (data_position + 4)])[0]
        data_position += 4
        self.destination_mask_length = unpack(">i", datagram[data_position : (data_position + 4)])[0]

    def __repr__(self):
        return f"""
            Extended Router:
                Next Hop Address: {self.next_hop}
                Source Mask Length: {self.source_mask_length}
                Destination Mask Length: {self.destination_mask_length}
        """

    def __len__(self):
        return 1


class sFlowExtendedGateway:
    "flowData: enterprise = 0, format = 1003"

    def __init__(self, datagram):
        self.address_type = unpack(">i", datagram[0:4])[0]
        if self.address_type == 1:
            self.next_hop = inet_ntop(AF_INET, datagram[4:8])
            data_position = 8
        elif self.address_type == 2:
            self.next_hop = inet_ntop(AF_INET6, datagram[4:20])
            data_position = 20
        else:
            self.next_hop = 0
            self.asn = 0
            self.source_asn = 0
            self.source_peer_asn = 0
            self.as_path_type = 0
            self.as_path_count = 0
            self.destination_as_path = []
            self.communities = []
            self.local_preference = 0
            return
        self.asn = unpack(">i", datagram[data_position : (data_position + 4)])[0]
        data_position += 4
        self.source_asn = unpack(">i", datagram[data_position : (data_position + 4)])[0]
        data_position += 4
        self.source_peer_asn = unpack(">i", datagram[data_position : (data_position + 4)])[0]
        data_position += 4
        self.as_path_type = unpack(">i", datagram[data_position : (data_position + 4)])[0]
        data_position += 4
        self.as_path_count = unpack(">i", datagram[data_position : (data_position + 4)])[0]
        data_position += 4
        self.destination_as_path = unpack(
            f'>{"i" * self.as_path_count}', datagram[data_position : (data_position + self.as_path_count * 4)]
        )  # TODO: Double Check
        data_position += self.as_path_count * 4
        self.community_count = unpack(">i", datagram[data_position : (data_position + 4)])[0]
        data_position += 4
        self.communities = unpack(
            f'>{"i" * self.community_count}',
            datagram[data_position : (data_position + self.community_count * 4)],  # TODO: Double Check
        )
        data_position += self.community_count * 4
        self.local_preference = unpack(">i", datagram[data_position : (data_position + 4)])[0]

    def __repr__(self):
        return f"""
            Extended Gateway:
                Next Hop Address: {self.next_hop}
                ASN: {self.asn}
                Source ASN: {self.source_asn}
                Source Peer ASN: {self.source_peer_asn}
                AS Path Typr: {self.as_path_type}
                AS Path Count: {self.as_path_count}
                Destination ASN: {self.destination_as_path}
                Community Count: {self.community_count}
                Communities: {self.communities}
                Local Preference: {self.local_preference}
        """

    def __len__(self):
        return 1


class sFlowExtendedUser:
    "flowData: enterprise = 0, format = 1004"

    def __init__(self, datagram):
        self.source_character_set = unpack(">i", datagram[0:4])
        name_length = unpack(">i", datagram[4:8])[0]
        self.source_user = datagram[8 : (8 + name_length)].decode("utf-8")
        data_position = name_length + (4 - name_length) % 4
        self.destination_character_set = datagram[data_position : (data_position + name_length)].decode("utf-8")
        data_position += 4
        name_length = unpack(">i", datagram[4:8])[0]
        self.destination_user = datagram[data_position : (data_position + name_length)].decode("utf-8")

    def __repr__(self):
        return f"""
            Extended User:
                Source Character Set: {self.source_character_set}
                Source User: {self.source_user}
                Destination Character Set: {self.destination_character_set}
                Destination User: {self.destination_user}
        """

    def __len__(self):
        return 1


class sFlowExtendedUrl:
    "flowData: enterprise = 0, format = 1005"

    def __init__(self, datagram):
        self.direction = unpack(">i", datagram[0:4])[0]
        name_length = min(unpack(">i", datagram[4:8])[0], 255)
        data_position = 8
        self.url = datagram[data_position : (data_position + name_length)].decode("utf-8")
        data_position += name_length + (4 - name_length) % 4
        name_length = min(unpack(">i", datagram[data_position : (data_position + 4)])[0], 255)
        data_position += 4
        self.host = datagram[data_position : (data_position + name_length)].decode("utf-8")
        name_length = unpack(">i", datagram[0:4])[0]
        self.port_name = datagram[data_position : (data_position + name_length)].decode("utf-8")

    def __repr__(self):
        return f"""
            Extended URL:
                URL: {self.url}
                Host: {self.host}
                Port: {self.port_name}
                Direction: {self.direction}
        """

    def __len__(self):
        return 1


class sFlowExtendedMpls:
    "flowData: enterprise = 0, format = 1006"

    def __init__(self, datagram):
        self.address_type = unpack(">i", datagram[0:4])[0]
        data_position = 4
        if self.address_type == 1:
            self.next_hop = inet_ntop(AF_INET, datagram[data_position : (data_position + 4)])
            data_position += 4
        elif self.address_type == 2:
            self.next_hop = inet_ntop(AF_INET6, datagram[data_position : (data_position + 16)])
            data_position += 16
        else:
            self.next_hop = 0
            self.in_label_stack_count = 0
            self.in_label_stack = []
            self.out_label_stack_count = 0
            self.out_label_stack = []
            return
        self.in_label_stack_count = unpack(">i", datagram[data_position : (data_position + 4)])[0]
        data_position += 4
        self.in_label_stack = unpack(
            f'>{"i" * self.in_label_stack_count}', datagram[data_position : (data_position + self.in_label_stack_count * 4)]
        )  # TODO: Double Check
        data_position += self.in_label_stack_count * 4
        self.out_label_stack_count = unpack(">i", datagram[data_position : (data_position + 4)])[0]
        data_position += 4
        self.out_label_stack = unpack(
            f'>{"i" * self.out_label_stack_count}', datagram[data_position : (data_position + self.out_label_stack_count * 4)]
        )  # TODO: Double Check

    def __repr__(self):
        return f"""
            Extended MPLS:
                Next Hop: {self.next_hop}
                In Label Stack Count: {self.in_label_stack_count}
                In Label Stack: {self.in_label_stack}
                Out Label Stack Count: {self.out_label_stack_count}
                Out Label Stack: { self.out_label_stack}
        """

    def __len__(self):
        return 1


class sFlowExtendedNat:
    "flowData: enterprise = 0, format = 1007"

    def __init__(self, datagram):
        self.source_address_type = unpack(">i", datagram[0:4])[0]
        data_position = 4
        if self.source_address_type == 1:
            self.source_address = inet_ntop(AF_INET, datagram[data_position : (data_position + 4)])
            data_position += 4
        elif self.source_address_type == 2:
            self.source_address = inet_ntop(AF_INET6, datagram[data_position : (data_position + 16)])
            data_position += 16
        else:
            self.source_address = 0
            self.destination_address = 0
            return
        self.destination_address_type = unpack(">i", datagram[0:4])[0]
        data_position += 4
        if self.destination_address_type == 1:
            self.destination_address = inet_ntop(AF_INET, datagram[data_position : (data_position + 4)])
            data_position += 4
        elif self.destination_address_type == 2:
            self.destination_address = inet_ntop(AF_INET6, datagram[data_position : (data_position + 16)])
            data_position += 16
        else:
            self.destination_address = 0
            return

    def __repr__(self):
        return f"""
            Extended NAT:
                Source Address: {self.source_address}
                Destination Address: {self.destination_address}
        """

    def __len__(self):
        return 1


class sFlowExtendedMplsTunnel:
    "flowData: enterprise = 0, format = 1008"

    def __init__(self, datagram):
        name_length = min(unpack(">i", datagram[0:4])[0], 255)
        self.host = datagram[4 : (4 + name_length)].decode("utf-8")
        data_position = 4 + name_length + (4 - name_length) % 4
        self.tunnel_id = unpack(">i", datagram[data_position : (data_position + 4)])[0]
        data_position += 4
        self.tunnel_cos = unpack(">i", datagram[data_position : (data_position + 4)])[0]

    def __repr__(self):
        return f"""
            Extended MPLS Tunnel:
                Host: {self.host}
                Tunnel ID: {self.tunnel_id}
                Tunnel COS: {self.tunnel_cos}
        """

    def __len__(self):
        return 1


class sFlowExtendedMplsVc:
    "flowData: enterprise = 0, format = 1009"

    def __init__(self, datagram):
        name_length = min(unpack(">i", datagram[0:4])[0], 255)
        self.vc_instance_name = datagram[4 : (4 + name_length)].decode("utf-8")
        data_position = 4 + name_length + (4 - name_length) % 4
        self.vll_vc_id = unpack(">i", datagram[data_position : (data_position + 4)])[0]
        data_position += 4
        self.vc_label_cos = unpack(">i", datagram[data_position : (data_position + 4)])[0]

    def __repr__(self):
        return f"""
            Extended MPLS Virtual Circuit:
                VC Instance Name: {self.vc_instance_name}
                VLL VC ID: {self.vll_vc_id}
                VC Label COS: {self.vc_label_cos}
        """

    def __len__(self):
        return 1


class sFlowExtendedMpls_FTN:
    "flowData: enterprise = 0, format = 1010"

    def __init__(self, datagram):
        name_length = min(unpack(">i", datagram[0:4])[0], 255)
        self.mpls_ftn_description = datagram[4 : (4 + name_length)].decode("utf-8")
        data_position = 4 + name_length + (4 - name_length) % 4
        self.mpls_ftn_mask = unpack(">i", datagram[data_position : (data_position + 4)])[0]

    def __repr__(self):
        return f"""
            Extended MPLS FTN:
                Description: {self.mpls_ftn_description}
                Mask: {self.mpls_ftn_mask}
        """

    def __len__(self):
        return 1


class sFlowExtendedMpls_LDP_FEC:
    "flowData: enterprise = 0, format = 1011"

    def __init__(self, datagram):
        self.mpls_fec_address_prefix_length = unpack(">i", datagram)[0]

    def __repr__(self):
        return f"""
            Extended MPLS LDP FEC:
                LDP FEC Address Prefix Length: {self.mpls_fec_address_prefix_length}
        """

    def __len__(self):
        return 1


class sFlowExtendedVlantunnel:
    "flowData: enterprise = 0, format = 1012"

    def __init__(self, datagram):
        stack_count = unpack(">i", datagram[0:4])[0]
        self.stack = unpack(f'>{"i" * stack_count}', datagram[4 : (4 + stack_count * 4)])

    def __repr__(self):
        return f"""
            Extended VLAN Tunnel:
                Stack: {self.stack}
        """

    def __len__(self):
        return 1


class sFlowExtendedSocketIpv4:
    "flowData: enterprise = 0, format = 2100"

    def __init__(self, datagram):
        self.protocol = unpack(">i", datagram[0:4])[0]
        self.local_ip = inet_ntop(AF_INET, datagram[4:8])
        self.remote_ip = inet_ntop(AF_INET, datagram[8:12])
        self.local_port = unpack(">i", datagram[12:16])[0]
        self.remote_port = unpack(">i", datagram[16:20])[0]

    def __repr__(self):
        return f"""
            Extended IPv4 Socket:
                Protocol: {self.protocol}
                Local IP: {self.local_ip}
                Local Port: {self.local_port}
                Remote IP: {self.remote_ip}
                Remote Port: {self.remote_port}
        """

    def __len__(self):
        return 1


class sFlowExtendedSocketIpv6:
    "flowData: enterprise = 0, format = 2101"

    def __init__(self, datagram):
        self.protocol = unpack(">i", datagram[0:4])[0]
        self.local_ip = inet_ntop(AF_INET6, datagram[4:20])
        self.remote_ip = inet_ntop(AF_INET6, datagram[20:36])
        self.local_port = unpack(">i", datagram[36:40])[0]
        self.remote_port = unpack(">i", datagram[40:44])[0]

    def __repr__(self):
        return f"""
            Extended IPv6 Socket:
                Protocol: {self.protocol}
                Local IP: {self.local_ip}
                Local Port: {self.local_port}
                Remote IP: {self.remote_ip}
                Remote Port: {self.remote_port}
        """

    def __len__(self):
        return 1


# Counter Record Types


class sFlowIfCounters:
    "counterData: enterprise = 0, format = 1"

    def __init__(self, datagram):
        self.index = unpack(">i", datagram[0:4])[0]
        self.type = unpack(">i", datagram[4:8])[0]
        self.speed = unpack(">q", datagram[8:16])[0]  # 64-bit
        self.direction = unpack(">i", datagram[16:20])[0]
        self.status = unpack(">i", datagram[20:24])[0]  # This is really a 2-bit value
        self.input_octets = unpack(">q", datagram[24:32])[0]  # 64-bit
        self.input_packets = unpack(">i", datagram[32:36])[0]
        self.input_multicast = unpack(">i", datagram[36:40])[0]
        self.input_broadcast = unpack(">i", datagram[40:44])[0]
        self.input_discarded = unpack(">i", datagram[44:48])[0]
        self.input_errors = unpack(">i", datagram[48:52])[0]
        self.input_unknown = unpack(">i", datagram[52:56])[0]
        self.output_octets = unpack(">q", datagram[56:64])[0]  # 64-bit
        self.output_packets = unpack(">i", datagram[64:68])[0]
        self.output_multicast = unpack(">i", datagram[68:72])[0]
        self.output_broadcast = unpack(">i", datagram[72:76])[0]
        self.output_discarded = unpack(">i", datagram[76:80])[0]
        self.output_errors = unpack(">i", datagram[80:84])[0]
        self.promiscuous = unpack(">i", datagram[84:88])[0]

    def __repr__(self) -> str:
        return f"""
            Interface Counters:
                Index: {self.index}
                Type: {self.type}
                Speed: {self.speed}
                Direction: {self.direction}
                Status: {self.status}
                In Octets: {self.input_octets}
                In Packets: {self.input_packets}
                In Multicast: {self.input_multicast}
                In Broadcast: {self.input_broadcast}
                In Discards: {self.input_discarded}
                In Errors: {self.input_errors}
                In Unknown: {self.input_unknown}
                Out Octets: {self.output_octets}
                Out Packets: {self.output_packets}
                Out Multicast: {self.output_multicast}
                Out Broadcast: {self.output_broadcast}
                Out Discard: {self.output_discarded}
                Out Errors: {self.output_errors}
                Promiscuous: {self.promiscuous}
        """

    def __len__(self):
        return 1


class sFlowEthernetInterface:
    "counterData: enterprise = 0, format = 2"

    def __init__(self, datagram):
        self.alignment_error = unpack(">i", datagram[0:4])[0]
        self.fcs_error = unpack(">i", datagram[4:8])[0]
        self.single_collision = unpack(">i", datagram[8:12])[0]
        self.multiple_collision = unpack(">i", datagram[12:16])[0]
        self.sqe_test = unpack(">i", datagram[16:20])[0]
        self.deferred = unpack(">i", datagram[20:24])[0]
        self.late_collision = unpack(">i", datagram[24:28])[0]
        self.excessive_collision = unpack(">i", datagram[28:32])[0]
        self.internal_transmit_error = unpack(">i", datagram[32:36])[0]
        self.carrier_sense_error = unpack(">i", datagram[36:40])[0]
        self.frame_too_long = unpack(">i", datagram[40:44])[0]
        self.internal_receive_error = unpack(">i", datagram[44:48])[0]
        self.symbol_error = unpack(">i", datagram[48:52])[0]

    def __repr__(self):
        return f"""
            Ethernet Counters:
                Alignment Errors: {self.alignment_error}
                FCS Errors: {self.fcs_error}
                Single Collisions: {self.single_collision}
                Multiple Collisions: {self.multiple_collision}
                SQE Tests: {self.sqe_test}
                Defered: {self.deferred}
                Late Collisions: {self.late_collision}
                Excessive Collisions: {self.excessive_collision}
                Internal Transmit Errors: {self.internal_transmit_error}
                Carrier Sense Error: {self.carrier_sense_error}
                Frame Too Long: {self.frame_too_long}
                Internal Receive Error: {self.internal_receive_error}
                Symbol Errors: {self.symbol_error}
        """

    def __len__(self):
        return 1


class sFlowTokenringCounters:
    "counterData: enterprise = 0, format = 3"

    def __init__(self, datagram):
        self.line_errors = unpack(">i", datagram[0:4])[0]
        self.burst_errors = unpack(">i", datagram[4:8])[0]
        self.ac_errors = unpack(">i", datagram[8:12])[0]
        self.abort_trans_errors = unpack(">i", datagram[12:16])[0]
        self.internal_errors = unpack(">i", datagram[16:20])[0]
        self.lost_frame_errors = unpack(">i", datagram[20:24])[0]
        self.receive_congestions = unpack(">i", datagram[24:28])[0]
        self.frame_copied_errors = unpack(">i", datagram[28:32])[0]
        self.token_errors = unpack(">i", datagram[32:36])[0]
        self.soft_errors = unpack(">i", datagram[36:40])[0]
        self.hard_errors = unpack(">i", datagram[40:44])[0]
        self.signal_loss = unpack(">i", datagram[44:48])[0]
        self.transmit_beacons = unpack(">i", datagram[48:52])[0]
        self.recoverys = unpack(">i", datagram[52:56])[0]
        self.lobe_wires = unpack(">i", datagram[56:60])[0]
        self.removes = unpack(">i", datagram[60:64])[0]
        self.singles = unpack(">i", datagram[64:68])[0]
        self.freq_errors = unpack(">i", datagram[68:72])[0]

    def __repr__(self):
        return f"""
            Token Ring Counters:
                Line Errors: {self.line_errors}
                Burst Errors: {self.burst_errors}
                AC Errors: {self.ac_errors}
                Abort Transmit Errors: {self.abort_trans_errors}
                Internal Errors: {self.internal_errors}
                Lost Frame Errors: {self.lost_frame_errors}
                Receive Congestions: {self.receive_congestions}
                Frame Copied Errors: {self.frame_copied_errors}
                Token Errors: {self.token_errors}
                Soft Errors: {self.soft_errors}
                Hard Errors: {self.hard_errors}
                Signal Lost: {self.signal_loss}
                Transmit Beacons: {self.transmit_beacons}
                Recoverys: {self.recoverys}
                Lobe Wires: {self.lobe_wires}
                Removes: {self.removes}
                Singles: {self.singles}
                Frequency Errors: {self.freq_errors}
        """

    def __len__(self):
        return 1


class sFlowVgCounters:
    "counterData: enterprise = 0, format = 4"

    def __init__(self, datagram):
        self.in_high_priority_frames = unpack(">i", datagram[0:4])[0]
        self.in_high_priority_octets = unpack(">q", datagram[4:12])[0]
        self.in_norm_priority_frames = unpack(">i", datagram[12:16])[0]
        self.in_norm_priority_octets = unpack(">q", datagram[16:24])[0]
        self.in_ipm_errors = unpack(">i", datagram[24:28])[0]
        self.in_oversize_frame_errors = unpack(">i", datagram[28:32])[0]
        self.in_data_errors = unpack(">i", datagram[32:36])[0]
        self.in_null_addressed_frames = unpack(">i", datagram[36:40])[0]
        self.out_high_priority_frames = unpack(">i", datagram[40:44])[0]
        self.out_high_priority_octets = unpack(">q", datagram[44:52])[0]
        self.transition_into_trainings = unpack(">i", datagram[52:56])[0]
        self.hc_in_high_priority_octets = unpack(">q", datagram[56:64])[0]
        self.hc_in_norm_priority_octets = unpack(">q", datagram[64:72])[0]
        self.hc_out_high_priority_octets = unpack(">q", datagram[72:80])[0]

    def __repr__(self):
        return f"""
            VG Counters:
                In High Priority Frames: {self.in_high_priority_frames}
                In High Priority Octets: {self.in_high_priority_octets}
                In Normal Priority Frames: {self.in_norm_priority_frames}
                In Normal Priority Octets: {self.in_norm_priority_octets}
                In IMP Errors: {self.in_ipm_errors}
                In Oversize Frame Errors: {self.in_oversize_frame_errors}
                In Data Errors: {self.in_data_errors}
                In Null Addressed Frames: {self.in_null_addressed_frames}
                Out High Priority Frames: {self.out_high_priority_frames}
                Out High Priority Octets: {self.out_high_priority_octets}
                Transition into Trainings: {self.transition_into_trainings}
                HC in High Priority Octets: {self.hc_in_high_priority_octets}
                HC in Normal Priority Octets: {self.hc_in_norm_priority_octets}
                HS Out High Priority Octets: {self.hc_out_high_priority_octets}
        """

    def __len__(self):
        return 1


class sFlowVLAN:
    "counterData: enterprise = 0, format = 5"

    def __init__(self, datagram):
        self.vlan_id = unpack(">i", datagram[0:4])[0]
        self.octets = unpack(">q", datagram[4:12])[0]  # 64-bit
        self.unicast = unpack(">i", datagram[12:16])[0]
        self.multicast = unpack(">i", datagram[16:20])[0]
        self.broadcast = unpack(">i", datagram[20:24])[0]
        self.discard = unpack(">i", datagram[24:28])[0]

    def __repr__(self):
        return f"""
            VLAN Counters:
                VLAN ID: {self.vlan_id}
                Octets: {self.octets}
                Unicast: {self.unicast}
                Multicast: {self.multicast}
                Broadcast: {self.broadcast}
                Discard: {self.discard}
        """

    def __len__(self):
        return 1


class sFlowProcessor:
    "counterData: enterprise = 0, format = 1001"

    def __init__(self, datagram):
        self.cpu_5s = unpack(">i", datagram[0:4])[0]
        self.cpu_1m = unpack(">i", datagram[4:8])[0]
        self.cpu_5m = unpack(">i", datagram[8:12])[0]
        self.total_memory = unpack(">q", datagram[12:20])[0]  # 64-bit
        self.free_memory = unpack(">q", datagram[20:28])[0]  # 64-bit

    def __repr__(self):
        return f"""
            Processor Counters:
                CPU 5s: {self.cpu_5s}
                CPU 1m: {self.cpu_1m}
                CPU 5m: {self.cpu_5m}
                Total Memory: {self.total_memory}
                Free Memory: {self.free_memory}
        """

    def __len__(self):
        return 1


class sFlowOfPort:
    "counterData: enterprise = 0, format = 1004"

    def __init__(self, datagram):
        self.data_path_id = unpack(">i", datagram[0:8])[0]
        self.port_number = unpack(">i", datagram[8:12])[0]

    def __repr__(self):
        return f"""
            OpenFlow Port:
                Data Path ID: {self.data_path_id}
                Port Number: {self.port_number}
        """

    def __len__(self):
        return 1


class sFlowPortName:
    "counterData: enterprise = 0, format = 1005"

    def __init__(self, datagram):
        name_length = unpack(">i", datagram[0:4])[0]
        self.port_name = datagram[4 : (4 + name_length)].decode("utf-8")

    def __repr__(self):
        return f"""
            OpenFlow Port Name:
                Port Name: {self.port_name}
        """

    def __len__(self):
        return 1


class sFlowHostDescr:
    "counterData: enterprise = 0, format = 2000"

    def __init__(self, datagram):
        name_length = min(unpack(">i", datagram[0:4])[0], 64)
        data_position = 4
        self.host_name = datagram[data_position : (data_position + name_length)].decode("utf-8")
        data_position += name_length + (4 - name_length) % 4
        self.uuid = UUID(bytes=datagram[data_position : (data_position + 16)])
        data_position = data_position + 16
        self.machine_type = unpack(">i", datagram[data_position : (data_position + 4)])[0]
        data_position = data_position + 4
        self.os_name = unpack(">i", datagram[data_position : (data_position + 4)])[0]
        data_position = data_position + 4
        name_length = min(unpack(">i", datagram[data_position : (data_position + 4)])[0], 32)
        data_position += 4
        self.os_release = datagram[data_position : (data_position + name_length)].decode("utf-8")

    def __repr__(self):
        return f"""
            Host Description:
                Host Name: {self.host_name}
                UUID: {self.uuid}
                Machine Type: {self.machine_type}
                Operating System: {self.os_name}
                OS Release: {self.os_release}
        """

    def __len__(self):
        return 1


class sFlowHostAdapters:
    "counterData: enterprise = 0, format = 2001"

    class hostAdapter:
        def __init__(self):
            self.if_index = None
            self.mac_address_count = None
            self.mac_addresses = None

        def __repr__(self):
            return f"""
                Adapater:
                    Interface Index: {self.if_index}
                    MAC Address Count: {self.mac_address_count}
                    MAC Addresses: {self.mac_addresses}
            """

    def __init__(self, datagram):
        self.adapters = []
        self.host_adapter_count = unpack(">i", datagram[0:4])[0]
        data_position = 4
        for _ in range(self.host_adapter_count):
            hostadapter = self.hostAdapter()
            hostadapter.if_index = unpack(">i", datagram[data_position : (data_position + 4)])[0]
            data_position += 4
            hostadapter.mac_address_count = unpack(">i", datagram[data_position : (data_position + 4)])[0]
            data_position += 4
            hostadapter.mac_addresses = []
            for mac_address in range(hostadapter.mac_address_count):
                hostadapter.mac_addresses.append(
                    datagram[(data_position + mac_address * 8) : (data_position + mac_address * 8 + 6)]
                ).hex("-")
            data_position += hostadapter.mac_address_count * 8
            self.adapters.append(hostadapter)

    def __repr__(self):
        response = f"""
            Host Adapters:
                Host Adapater Count: {self.host_adapter_count}
        """

        for adapater in self.adapters:
            response += repr(adapater)

        return response

    def __len__(self):
        return self.host_adapter_count


class sFlowHostParent:
    "counterData: enterprise = 0, format = 2002"

    def __init__(self, datagram):
        self.container_type = unpack(">i", datagram[0:4])[0]
        self.container_index = unpack(">i", datagram[4:8])[0]

    def __repr__(self):
        return f"""
            Host Parent:
                Container Type: {self.container_type}
                Container Index: {self.container_index}
        """

    def __len__(self):
        return 1


class sFlowHostCPU:
    "counterData: enterprise = 0, format = 2003"

    def __init__(self, datagram):
        self.average_load_1_minute = unpack(">f", datagram[0:4])[0]  # Floating Point
        self.average_load_5_minutes = unpack(">f", datagram[4:8])[0]  # Floating Point
        self.average_load_15_minutes = unpack(">f", datagram[8:12])[0]  # Floating Point
        self.running_processes = unpack(">i", datagram[12:16])[0]
        self.total_processes = unpack(">i", datagram[16:20])[0]
        self.number_cpus = unpack(">i", datagram[20:24])[0]
        self.cpu_mhz = unpack(">i", datagram[24:28])[0]
        self.uptime = unpack(">i", datagram[28:32])[0]
        self.user_time = unpack(">i", datagram[32:36])[0]
        self.nice_time = unpack(">i", datagram[36:40])[0]
        self.system_time = unpack(">i", datagram[40:44])[0]
        self.idle_time = unpack(">i", datagram[44:48])[0]
        self.io_wait_time = unpack(">i", datagram[48:52])[0]
        self.intrupt_time = unpack(">i", datagram[52:56])[0]
        self.soft_interrupt_time = unpack(">i", datagram[56:60])[0]
        self.interrupt_count = unpack(">i", datagram[60:64])[0]
        self.context_switch = unpack(">i", datagram[64:68])[0]
        # self.virtual_instance = unpack(">i", datagram[68:72])[0]
        # self.guest_os = unpack(">i", datagram[72:76])[0]
        # self.guest_nice = unpack(">i", datagram[76:80])[0]

    def __repr__(self):
        return f"""
            Host CPU Counters:
                Average Load 1 Minute: {self.average_load_1_minute}
                Average Load 5 Minutes: {self.average_load_5_minutes}
                Average Load 15 Minutes: {self.average_load_15_minutes}
                Running Processes: {self.running_processes}
                Total Processes: {self.total_processes}
                Number of CPUs: {self.number_cpus}
                CPU Speed in MHz: {self.cpu_mhz}
                System Uptime: {self.system_time}
                User Time: {self.user_time}
                NICE Time: {self.nice_time}
                System Time: {self.system_time}
                Idle Time: {self.idle_time}
                I/O Wait Time: {self.io_wait_time}
                Interupt Time: {self.soft_interrupt_time}
                Soft Interrupt Time: {self.soft_interrupt_time}
                Interrupt Count: {self.interrupt_count}
                Context Switches: {self.context_switch}
        """

    def __len__(self):
        return 1


class sFlowHostMemory:
    "counterData: enterprise = 0, format = 2004"

    def __init__(self, datagram):
        self.memory_total = unpack(">q", datagram[0:8])[0]  # 64-bit
        self.memory_free = unpack(">q", datagram[8:16])[0]  # 64-bit
        self.memory_shared = unpack(">q", datagram[16:24])[0]  # 64-bit
        self.memory_buffers = unpack(">q", datagram[24:32])[0]  # 64-bit
        self.memory_cache = unpack(">q", datagram[32:40])[0]  # 64-bit
        self.swap_total = unpack(">q", datagram[40:48])[0]  # 64-bit
        self.swap_free = unpack(">q", datagram[48:56])[0]  # 64-bit
        self.page_in = unpack(">i", datagram[56:60])[0]
        self.page_out = unpack(">i", datagram[60:64])[0]
        self.swap_in = unpack(">i", datagram[64:68])[0]
        self.swap_out = unpack(">i", datagram[68:72])[0]

    def __repr__(self):
        return f"""
            Host Memory Counters:
                Memory Total: {self.memory_total}
                Memory Free: {self.memory_free}
                Memory Shared: {self.memory_shared}
                Memory Buffers: {self.memory_buffers}
                Memory Cache: {self.memory_cache}
                Swap Total: {self.swap_total}
                Swap Free: {self.swap_free}
                Page In: {self.page_in}
                Page Out: {self.page_out}
                Swap In: {self.swap_in}
                Swap Out: {self.swap_out}
        """

    def __len__(self):
        return 1


class sFlowHostDiskIO:
    "counterData: enterprise = 0, format = 2005"

    def __init__(self, datagram):
        self.disk_total = unpack(">q", datagram[0:8])[0]  # 64-bit
        self.disk_free = unpack(">q", datagram[8:16])[0]  # 64-bit
        self.partition_max_used = (unpack(">i", datagram[16:20])[0]) / float(100)
        self.read = unpack(">i", datagram[20:24])[0]
        self.read_bytes = unpack(">q", datagram[24:32])[0]  # 64-bit
        self.read_time = unpack(">i", datagram[32:36])[0]
        self.write = unpack(">i", datagram[36:40])[0]
        self.write_bytes = unpack(">q", datagram[40:48])[0]  # 64-bit
        self.write_time = unpack(">i", datagram[48:52])[0]

    def __repr__(self):
        return f"""
            Host Disk I/O Counters:
                Disk Total: {self.disk_total}
                Disk Free: {self.disk_free}
                Partition Max Used: {self.partition_max_used}
                Read: {self.read}
                Read Bytes: {self.read_bytes}
                Read Time: {self.read_time}
                Write: {self.write}
                Write Bytes: {self.write_bytes}
                Write Time: {self.write_time}
        """

    def __len__(self):
        return 1


class sFlowHostNetIO:
    "counterData: enterprise = 0, format = 2006"

    def __init__(self, datagram):
        self.in_byte = unpack(">q", datagram[0:8])[0]  # 64-bit
        self.in_packet = unpack(">i", datagram[8:12])[0]
        self.in_error = unpack(">i", datagram[12:16])[0]
        self.in_drop = unpack(">i", datagram[16:20])[0]
        self.out_byte = unpack(">q", datagram[20:28])[0]  # 64-bit
        self.out_packet = unpack(">i", datagram[28:32])[0]
        self.out_error = unpack(">i", datagram[32:36])[0]
        self.out_drop = unpack(">i", datagram[36:40])[0]

    def __repr__(self):
        return f"""
            Host Network I/O Counters:
                In Bytes: {self.in_byte}
                In Packets: {self.in_packet}
                In Errors: {self.in_error}
                In Drop: {self.in_drop}
                Out Byte: {self.out_byte}
                Out Packet: {self.out_packet}
                Out Erros: {self.out_error}
                Out Drop: {self.out_drop}
        """

    def __len__(self):
        return 1


class sFlowMib2IP:
    "counterData: enterprise = 0, format = 2007"

    def __init__(self, datagram):
        self.forwarding = unpack(">i", datagram[0:4])[0]
        self.default_ttl = unpack(">i", datagram[4:8])[0]
        self.in_receives = unpack(">i", datagram[8:12])[0]
        self.in_header_errors = unpack(">i", datagram[12:16])[0]
        self.in_address_errors = unpack(">i", datagram[16:20])[0]
        self.in_forward_datagrams = unpack(">i", datagram[20:24])[0]
        self.in_unknown_protocols = unpack(">i", datagram[24:28])[0]
        self.in_discards = unpack(">i", datagram[28:32])[0]
        self.in_delivers = unpack(">i", datagram[32:36])[0]
        self.out_requests = unpack(">i", datagram[36:40])[0]
        self.out_discards = unpack(">i", datagram[40:44])[0]
        self.out_no_routes = unpack(">i", datagram[44:48])[0]
        self.reassembly_timeout = unpack(">i", datagram[48:52])[0]
        self.reassembly_required = unpack(">i", datagram[52:56])[0]
        self.reassembly_okay = unpack(">i", datagram[56:60])[0]
        self.reassembly_fail = unpack(">i", datagram[60:64])[0]
        self.fragment_okay = unpack(">i", datagram[64:68])[0]
        self.fragment_fail = unpack(">i", datagram[68:72])[0]
        self.fragment_create = unpack(">i", datagram[72:76])[0]

    def __repr__(self):
        return f"""
            MIB2 IP Counters:
                Forwarding: {self.forwarding}
                Default TTL: {self.default_ttl}
                In Receives: {self.in_receives}
                In Header Errors: {self.in_header_errors}
                In Address Errors: {self.in_address_errors}
                In Forward Datagrams: {self.in_forward_datagrams}
                In Unknown Protocols: {self.in_unknown_protocols}
                In Discards: {self.in_discards}
                In Delivers: {self.in_delivers}
                Out Requests: {self.out_requests}
                Out Discards: {self.out_discards}
                Out No Routes: {self.out_no_routes}
                Reassembly Timeout: {self.reassembly_timeout}
                Reassembly Required: {self.reassembly_required}
                Reassembly Okay: {self.reassembly_okay}
                Reassembly Fail: {self.reassembly_fail}
                Fragment Okay: {self.fragment_okay}
                Fragment Fail: {self.fragment_fail}
                Fragment Create: {self.fragment_create}
        """

    def __len__(self):
        return 1


class sFlowMib2ICMP:
    "counterData: enterprise = 0, format = 2008"

    def __init__(self, datagram):
        self.in_message = unpack(">i", datagram[0:4])[0]
        self.in_error = unpack(">i", datagram[4:8])[0]
        self.in_destination_unreachable = unpack(">i", datagram[8:12])[0]
        self.in_time_exceeded = unpack(">i", datagram[12:16])[0]
        self.in_parameter_problem = unpack(">i", datagram[16:20])[0]
        self.in_source_quence = unpack(">i", datagram[20:24])[0]
        self.in_redirect = unpack(">i", datagram[24:28])[0]
        self.in_echo = unpack(">i", datagram[28:32])[0]
        self.in_echo_reply = unpack(">i", datagram[32:36])[0]
        self.in_timestamp = unpack(">i", datagram[36:40])[0]
        self.in_address_mask = unpack(">i", datagram[40:44])[0]
        self.in_address_mask_reply = unpack(">i", datagram[44:48])[0]
        self.out_message = unpack(">i", datagram[48:52])[0]
        self.out_error = unpack(">i", datagram[52:56])[0]
        self.out_destination_unreachable = unpack(">i", datagram[56:60])[0]
        self.out_time_exceeded = unpack(">i", datagram[60:64])[0]
        self.out_parameter_problem = unpack(">i", datagram[64:68])[0]
        self.out_source_quence = unpack(">i", datagram[68:72])[0]
        self.out_redirect = unpack(">i", datagram[72:76])[0]
        self.out_echo = unpack(">i", datagram[76:80])[0]
        self.out_echo_reply = unpack(">i", datagram[80:84])[0]
        self.out_timestamp = unpack(">i", datagram[84:88])[0]
        self.out_timestamp_reply = unpack(">i", datagram[88:92])[0]
        self.out_address_mask = unpack(">i", datagram[92:96])[0]
        self.out_address_mask_reply = unpack(">i", datagram[96:100])[0]

    def __repr__(self):
        return f"""
            MIB2 ICMP Counters:
                In Message: {self.in_message}
                In Error: {self.in_error}
                In Destination Unreachable: {self.in_destination_unreachable}
                In Time Exceeded: {self.in_time_exceeded}
                In Paramater Problem: {self.in_parameter_problem}
                In Source Quence: {self.in_source_quence}
                In Echo: {self.in_echo}
                In Echo Reply: {self.in_echo_reply}
                In Timestamp: {self.in_timestamp}
                In Address Mask: {self.in_address_mask}
                In Address Mask Reply: {self.in_address_mask_reply}
                Out Message: {self.out_message}
                Out Error: {self.out_error}
                Out Destination Unreachable: {self.out_destination_unreachable}
                Out Time Exceeded: {self.out_time_exceeded}
                Out Parameter Problem: {self.out_parameter_problem}
                Out Source Quence: {self.out_source_quence}
                Out Redirect: {self.out_redirect}
                Out Echo: {self.out_echo}
                Out Echo Reply: {self.out_echo_reply}
                Out Timestamp: {self.out_timestamp}
                Out Timestamp Reply: {self.out_timestamp_reply}
                Out Address Mask: {self.out_address_mask}
                Out Address Mask Reply: {self.out_address_mask_reply}
        """

    def __len__(self):
        return 1


class sFlowMib2TCP:
    "counterData: enterprise = 0, format = 2009"

    def __init__(self, datagram):
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
        self.in_error = unpack(">i", datagram[48:52])[0]
        self.outReset = unpack(">i", datagram[52:56])[0]
        self.inCsumError = unpack(">i", datagram[56:60])[0]

    def __repr__(self):
        return f"""
            MIB2 TCP Counters:
                Incomplete
        """

    def __len__(self):
        return 1


class sFlowMib2UDP:
    "counterData: enterprise = 0, format = 2010"

    def __init__(self, datagram):
        self.inDatagrams = unpack(">i", datagram[0:4])[0]
        self.noPorts = unpack(">i", datagram[4:8])[0]
        self.in_errors = unpack(">i", datagram[8:12])[0]
        self.outDatagrams = unpack(">i", datagram[12:16])[0]
        self.receiveBufferError = unpack(">i", datagram[16:20])[0]
        self.sendBufferError = unpack(">i", datagram[20:24])[0]
        self.inCheckSumError = unpack(">i", datagram[24:28])[0]

    def __repr__(self):
        return f"""
            MIB2 UDP Counters:
                Incomplete
        """

    def __len__(self):
        return 1


class sFlowVirtNode:
    "counterData: enterprise = 0, format = 2100"

    def __init__(self, datagram):
        self.mhz = unpack(">i", datagram[0:4])[0]
        self.cpus = unpack(">i", datagram[4:8])[0]
        self.memory = unpack(">q", datagram[8:16])[0]
        self.memoryFree = unpack(">q", datagram[16:24])[0]
        self.numDomains = unpack(">i", datagram[24:28])[0]

    def __repr__(self):
        return f"""
            Virtual Node Counters:
                Incomplete
        """

    def __len__(self):
        return 1


class sFlowVirtCPU:
    "counterData: enterprise = 0, format = 2101"

    def __init__(self, datagram):
        self.state = unpack(">i", datagram[0:4])[0]
        self.cpuTime = unpack(">i", datagram[4:8])[0]
        self.nrVirtCpu = unpack(">i", datagram[8:12])[0]

    def __repr__(self):
        return f"""
            Virtual CPU Counters:
                Incomplete
        """

    def __len__(self):
        return 1


class sFlowVirtMemory:
    "counterData: enterprise = 0, format = 2102"

    def __init__(self, datagram):
        self.memory = unpack(">q", datagram[0:8])[0]
        self.maxMemory = unpack(">q", datagram[8:16])[0]

    def __repr__(self):
        return f"""
            Virtual Memory Counters:
                Incomplete
        """

    def __len__(self):
        return 1


class sFlowVirtDiskIO:
    "counterData: enterprise = 0, format = 2103"

    def __init__(self, datagram):
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
                Incomplete
        """

    def __len__(self):
        return 1


class sFlowVirtNetIO:
    "counterData: enterprise = 0, format = 2104"

    def __init__(self, datagram):
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
                Incomplete
        """

    def __len__(self):
        return 1


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

    def __init__(self, header, sample_type, datagram):
        self.header = header
        self.sample_type = sample_type
        self.enterprise, self.format = divmod(self.header, 4096)
        self.datagram = datagram
        self.record = s_flow_record_format.get((sample_type, self.enterprise, self.format), sFlowRecordBase)(datagram)


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
        self.enterprise, self.sample_type = divmod(sample_header, 4096)
        # 0 sample_data / 1 flow_data (single) / 2 counter_data (single)
        #             / 3 flow_data (expanded) / 4 counter_data (expanded)

        self.sequence = unpack(">i", datagram[0:4])[0]

        if self.sample_type in [1, 2]:
            sample_source = unpack(">i", datagram[4:8])[0]
            self.sourceType, self.sourceIndex = divmod(sample_source, 16777216)
            data_position = 8
        elif self.sample_type in [3, 4]:
            self.sourceType, self.sourceIndex = unpack(">ii", datagram[4:12])
            data_position = 12
        else:
            pass  # sampleTypeError
        self.records = []

        if self.sample_type in [1, 3]:  # Flow
            self.sampleRate, self.samplePool, self.droppedPackets = unpack(">iii", datagram[data_position : (data_position + 12)])
            data_position += 12
            if self.sample_type == 1:
                input_interface, output_interface = unpack(">ii", datagram[(data_position) : (data_position + 8)])
                data_position += 8
                self.inputIfFormat, self.inputIfValue = divmod(input_interface, 1073741824)
                self.outputIfFormat, self.outputIfValue = divmod(output_interface, 1073741824)
            elif self.sample_type == 3:
                self.inputIfFormat, self.inputIfValue, self.outputIfFormat, self.outputIfValue = unpack(
                    ">ii", datagram[data_position : (data_position + 16)]
                )
                data_position += 16
            self.recordCount = unpack(">i", datagram[data_position : data_position + 4])[0]
            data_position += 4

        elif self.sample_type in [2, 4]:  # Counters
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
            self.records.append(sFlowRecord(record_header, self.sample_type, record_data))
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
        self.address_type = unpack(">i", datagram[4:8])[0]
        if self.address_type == 1:
            self.agentAddress = inet_ntop(AF_INET, datagram[8:12])
            self.subAgent = unpack(">i", datagram[12:16])[0]
            self.sequenceNumber = unpack(">i", datagram[16:20])[0]
            self.sysUpTime = unpack(">i", datagram[20:24])[0]
            self.NumberSample = unpack(">i", datagram[24:28])[0]
            data_position = 28
        elif self.address_type == 2:
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
