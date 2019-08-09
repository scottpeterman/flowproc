# -*- coding: utf-8 -*-
"""
Code snippet copied from:

https://raw.githubusercontent.com/bitkeks/python-netflow-v9-softflowd/master/src/netflow/collector_v9.py

Copyright 2017, 2018 Dominik Pataky <dev@bitkeks.eu>
Licensed under MIT License. See LICENSE.

Noted by shuntingyard:

    In resource 
    https://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html
    Cisco states:

        For the information on the field types with the numbers
        between 128 and 32768, please refer to the IANA registry of
        IPFIX information elements at
        https://www.iana.org/assignments/ipfix/ipfix.xhtml.
"""

LABEL = {
    # Cisco specs for NetFlow v9
    # https://tools.ietf.org/html/rfc3954
    # https://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html
    1: 'IN_BYTES',
    2: 'IN_PKTS',
    3: 'FLOWS',
    4: 'PROTOCOL',
    5: 'SRC_TOS',
    6: 'TCP_FLAGS',
    7: 'L4_SRC_PORT',
    8: 'IPV4_SRC_ADDR',
    9: 'SRC_MASK',
    10: 'INPUT_SNMP',
    11: 'L4_DST_PORT',
    12: 'IPV4_DST_ADDR',
    13: 'DST_MASK',
    14: 'OUTPUT_SNMP',
    15: 'IPV4_NEXT_HOP',
    16: 'SRC_AS',
    17: 'DST_AS',
    18: 'BGP_IPV4_NEXT_HOP',
    19: 'MUL_DST_PKTS',
    20: 'MUL_DST_BYTES',
    21: 'LAST_SWITCHED',
    22: 'FIRST_SWITCHED',
    23: 'OUT_BYTES',
    24: 'OUT_PKTS',
    25: 'MIN_PKT_LNGTH',
    26: 'MAX_PKT_LNGTH',
    27: 'IPV6_SRC_ADDR',
    28: 'IPV6_DST_ADDR',
    29: 'IPV6_SRC_MASK',
    30: 'IPV6_DST_MASK',
    31: 'IPV6_FLOW_LABEL',
    32: 'ICMP_TYPE',
    33: 'MUL_IGMP_TYPE',
    34: 'SAMPLING_INTERVAL',
    35: 'SAMPLING_ALGORITHM',
    36: 'FLOW_ACTIVE_TIMEOUT',
    37: 'FLOW_INACTIVE_TIMEOUT',
    38: 'ENGINE_TYPE',
    39: 'ENGINE_ID',
    40: 'TOTAL_BYTES_EXP',
    41: 'TOTAL_PKTS_EXP',
    42: 'TOTAL_FLOWS_EXP',
    # 43 vendor proprietary
    44: 'IPV4_SRC_PREFIX',
    45: 'IPV4_DST_PREFIX',
    46: 'MPLS_TOP_LABEL_TYPE',
    47: 'MPLS_TOP_LABEL_IP_ADDR',
    48: 'FLOW_SAMPLER_ID',
    49: 'FLOW_SAMPLER_MODE',
    50: 'NTERVAL',
    # 51 vendor proprietary
    52: 'MIN_TTL',
    53: 'MAX_TTL',
    54: 'IPV4_IDENT',
    55: 'DST_TOS',
    56: 'IN_SRC_MAC',
    57: 'OUT_DST_MAC',
    58: 'SRC_VLAN',
    59: 'DST_VLAN',
    60: 'IP_PROTOCOL_VERSION',
    61: 'DIRECTION',
    62: 'IPV6_NEXT_HOP',
    63: 'BPG_IPV6_NEXT_HOP',
    64: 'IPV6_OPTION_HEADERS',
    # 65-69 vendor proprietary
    70: 'MPLS_LABEL_1',
    71: 'MPLS_LABEL_2',
    72: 'MPLS_LABEL_3',
    73: 'MPLS_LABEL_4',
    74: 'MPLS_LABEL_5',
    75: 'MPLS_LABEL_6',
    76: 'MPLS_LABEL_7',
    77: 'MPLS_LABEL_8',
    78: 'MPLS_LABEL_9',
    79: 'MPLS_LABEL_10',
    80: 'IN_DST_MAC',
    81: 'OUT_SRC_MAC',
    82: 'IF_NAME',
    83: 'IF_DESC',
    84: 'SAMPLER_NAME',
    85: 'IN_PERMANENT_BYTES',
    86: 'IN_PERMANENT_PKTS',
    # 87 vendor property
    88: 'FRAGMENT_OFFSET',
    89: 'FORWARDING_STATUS',
    90: 'MPLS_PAL_RD',
    91: 'MPLS_PREFIX_LEN',  # Number of consecutive bits in the MPLS prefix length.
    92: 'SRC_TRAFFIC_INDEX',  # BGP Policy Accounting Source Traffic Index
    93: 'DST_TRAFFIC_INDEX',  # BGP Policy Accounting Destination Traffic Index
    94: 'APPLICATION_DESCRIPTION',  # Application description
    95: 'APPLICATION_TAG',  # 8 bits of engine ID, followed by n bits of classification
    96: 'APPLICATION_NAME',  # Name associated with a classification
    98: 'postipDiffServCodePoint',  # The value of a Differentiated Services Code Point (DSCP) encoded in the Differentiated Services Field, after modification
    99: 'replication_factor',  # Multicast replication factor
    100: 'DEPRECATED',  # DEPRECATED
    102: 'layer2packetSectionOffset',  # Layer 2 packet section offset. Potentially a generic offset
    103: 'layer2packetSectionSize',  # Layer 2 packet section size. Potentially a generic size
    104: 'layer2packetSectionData',  # Layer 2 packet section data
    # 105-127 reserved for future use by Cisco

    # ASA extensions
    # https://www.cisco.com/c/en/us/td/docs/security/asa/special/netflow/guide/asa_netflow.html
    148: 'NF_F_CONN_ID',  # An identifier of a unique flow for the device
    176: 'NF_F_ICMP_TYPE',  # ICMP type value
    177: 'NF_F_ICMP_CODE',  # ICMP code value
    178: 'NF_F_ICMP_TYPE_IPV6',  # ICMP IPv6 type value
    179: 'NF_F_ICMP_CODE_IPV6',  # ICMP IPv6 code value
    225: 'NF_F_XLATE_SRC_ADDR_IPV4',  # Post NAT Source IPv4 Address
    226: 'NF_F_XLATE_DST_ADDR_IPV4',  # Post NAT Destination IPv4 Address
    227: 'NF_F_XLATE_SRC_PORT',  # Post NATT Source Transport Port
    228: 'NF_F_XLATE_DST_PORT',  # Post NATT Destination Transport Port
    281: 'NF_F_XLATE_SRC_ADDR_IPV6',  # Post NAT Source IPv6 Address
    282: 'NF_F_XLATE_DST_ADDR_IPV6',  # Post NAT Destination IPv6 Address
    233: 'NF_F_FW_EVENT',  # High-level event code
    33002: 'NF_F_FW_EXT_EVENT',  # Extended event code
    323: 'NF_F_EVENT_TIME_MSEC',  # The time that the event occurred, which comes from IPFIX
    152: 'NF_F_FLOW_CREATE_TIME_MSEC',
    231: 'NF_F_FWD_FLOW_DELTA_BYTES',  # The delta number of bytes from source to destination
    232: 'NF_F_REV_FLOW_DELTA_BYTES',  # The delta number of bytes from destination to source
    33000: 'NF_F_INGRESS_ACL_ID',  # The input ACL that permitted or denied the flow
    33001: 'NF_F_EGRESS_ACL_ID',  #  The output ACL that permitted or denied a flow
    40000: 'NF_F_USERNAME',  # AAA username

    # PaloAlto PAN-OS 8.0
    # https://www.paloaltonetworks.com/documentation/80/pan-os/pan-os/monitoring/netflow-monitoring/netflow-templates
    346: 'PANOS_privateEnterpriseNumber',
    56701: 'PANOS_APPID',
    56702: 'PANOS_USERID'
}

SCOPE_LABEL = {
    # https://tools.ietf.org/html/rfc3954#section-6.1
    1: "System",
    2: "Interface",
    3: "Line Card",
    4: "Cache",
    5: "Template",
}
