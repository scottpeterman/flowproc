# -*- coding: utf-8 -*-
"""
Various utility functions to convert port numbers, tcpflags, ICMP-type and code
to text

A `dict` to look up textual labels for protocol numbers and
a stopwatch decorator function

A class to reflect netflow exporter attributes and options
"""

import functools
import logging
import socket
import time

from ipaddress import ip_address

__author__ = "Tobias Frei"
__copyright__ = "Tobias Frei"
__license__ = "mit"

# globals
logger = logging.getLogger(__name__)


def stopwatch(fn):
    """
    Log (DEBUG) how much time is spent in decorated fn.
    """
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        start = time.perf_counter()
        result = fn(*args, **kwargs)
        end = time.perf_counter()
        msec = (end - start) * 1000
        # log results
        logger = fn.__globals__.get("logger", None)
        if logger:
            logger.debug(
                "{elapsed:4d} msec elapsed in '{name}'".format(
                    elapsed=int(round(msec, 1)), name=fn.__qualname__
                )
            )
        return result

    return wrapper


def port_to_str(port):
    """
    TODO
    """
    try:
        return socket.getservbyport(port)
    except OSError:
        return None


# ----- [ flag ] = label
TCPFLAGS = {}
TCPFLAGS[1 << 0] = "fin"
TCPFLAGS[1 << 1] = "syn"
TCPFLAGS[1 << 2] = "rst"
TCPFLAGS[1 << 3] = "psh"
TCPFLAGS[1 << 4] = "ack"
TCPFLAGS[1 << 5] = "urg"
TCPFLAGS[1 << 6] = "ecn"
TCPFLAGS[1 << 7] = "cwr"


def tcpflags_to_str(flags, brief=False):
    """Return TCP flags represented for humans.
    Args:
        flags   byte, binary value representing TCP flags
        brief   if true: short (8 byte `str`) representation,
                else: more verbose `list` representation
    Return:
        `str` or `list`
    """
    short = str()
    verbose = list()

    for key, label in TCPFLAGS.items():
        if key & flags == key:
            if brief:
                short += label[:1].upper()
            else:
                verbose.append(label)
        else:
            if brief:
                short += " "

    return short if brief else verbose


# @stopwatch
def fqdnlookup(ipa_str):
    """
    Return either the fqdn or an ipa
    """
    return socket.getfqdn(ipa_str)


# https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
PROTO = {
    0: "HOPOPT",
    1: "ICMP",
    2: "IGMP",
    3: "GGP",
    4: "IPv4",
    5: "ST",
    6: "TCP",
    7: "CBT",
    8: "EGP",
    9: "IGP",
    10: "BBN-RCC-MON",
    11: "NVP-II",
    12: "PUP",
    13: "ARGUS (deprecated)",
    14: "EMCON",
    15: "XNET",
    16: "CHAOS",
    17: "UDP",
    18: "MUX",
    19: "DCN-MEAS",
    20: "HMP",
    21: "PRM",
    22: "XNS-IDP",
    23: "TRUNK-1",
    24: "TRUNK-2",
    25: "LEAF-1",
    26: "LEAF-2",
    27: "RDP",
    28: "IRTP",
    29: "ISO-TP4",
    30: "NETBLT",
    31: "MFE-NSP",
    32: "MERIT-INP",
    33: "DCCP",
    34: "3PC",
    35: "IDPR",
    36: "XTP",
    37: "DDP",
    38: "IDPR-CMTP",
    39: "TP++",
    40: "IL",
    41: "IPv6",
    42: "SDRP",
    43: "IPv6-Route",
    44: "IPv6-Frag",
    45: "IDRP",
    46: "RSVP",
    47: "GRE",
    48: "DSR",
    49: "BNA",
    50: "ESP",
    51: "AH",
    52: "I-NLSP",
    53: "SWIPE (deprecated)",
    54: "NARP",
    55: "MOBILE",
    56: "TLSP",
    57: "SKIP",
    58: "IPv6-ICMP",
    59: "IPv6-NoNxt",
    60: "IPv6-Opts",
    61: "NaN",
    62: "CFTP",
    63: "NaN",
    64: "SAT-EXPAK",
    65: "KRYPTOLAN",
    66: "RVD",
    67: "IPPC",
    68: "NaN",
    69: "SAT-MON",
    70: "VISA",
    71: "IPCV",
    72: "CPNX",
    73: "CPHB",
    74: "WSN",
    75: "PVP",
    76: "BR-SAT-MON",
    77: "SUN-ND",
    78: "WB-MON",
    79: "WB-EXPAK",
    80: "ISO-IP",
    81: "VMTP",
    82: "SECURE-VMTP",
    83: "VINES",
    84: "TTP or IPTM",
    85: "NSFNET-IGP",
    86: "DGP",
    87: "TCF",
    88: "EIGRP",
    89: "OSPFIGP",
    90: "Sprite-RPC",
    91: "LARP",
    92: "MTP",
    93: "AX.25",
    94: "IPIP",
    95: "MICP (deprecated)",
    96: "SCC-SP",
    97: "ETHERIP",
    98: "ENCAP",
    99: "NaN",
    100: "GMTP",
    101: "IFMP",
    102: "PNNI",
    103: "PIM",
    104: "ARIS",
    105: "SCPS",
    106: "QNX",
    107: "A/N",
    108: "IPComp",
    109: "SNP",
    110: "Compaq-Peer",
    111: "IPX-in-IP",
    112: "VRRP",
    113: "PGM",
    114: "NaN",
    115: "L2TP",
    116: "DDX",
    117: "IATP",
    118: "STP",
    119: "SRP",
    120: "UTI",
    121: "SMP",
    122: "SM (deprecated)",
    123: "PTP",
    124: "ISIS over IPv4",
    125: "FIRE",
    126: "CRTP",
    127: "CRUDP",
    128: "SSCOPMCE",
    129: "IPLT",
    130: "SPS",
    131: "PIPE",
    132: "SCTP",
    133: "FC",
    134: "RSVP-E2E-IGNORE",
    135: "Mobility Header",
    136: "UDPLite",
    137: "MPLS-in-IP",
    138: "manet",
    139: "HIP",
    140: "Shim6",
    141: "WESP",
    142: "ROHC",
    255: "Reserved",
}


def dstport_to_icmptc(dstport):
    """
    Destination port to ICMP type- and code - definition taken from
    https://www.erg.abdn.ac.uk/users/gorry/course/inet-pages/icmp-code.html
    https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml

    Args:
        dstport     `int` destination port number
    Return:
        `int` icmp type, `int` icmp code
    """
    return int(dstport / 256), dstport % 256


# TODO This is work in progress...
ICMPTEXT = {
    (0, 0): "Echo Reply",
    (3, 0): "Net Unreachable",
    (3, 1): "Host Unreachable",
    (3, 2): "Protocol Unreachable",
    (3, 3): "Port Unreachable",
    (3, 4): "Fragmentation Needed and Don't Fragment was Set",
    (3, 5): "Source Route Failed",
    (3, 6): "Destination Network Unknown",
    (3, 7): "Destination Host Unknown",
    (3, 8): "Source Host Isolated",
    (3, 9): "Communication with Destination Network is Administratively Prohibited",
    (3, 10): "Communication with Destination Host is Administratively Prohibited",
    (3, 11): "Destination Network Unreachable for Type of Service",
    (3, 12): "Destination Host Unreachable for Type of Service",
    (3, 13): "Communication Administratively Prohibited    ",
    (3, 14): "Host Precedence Violation",
    (3, 15): "Precedence cutoff in effect",
    (5, 0): "Redirect Datagram for the Network (or subnet)",
    (5, 1): "Redirect Datagram for the Host",
    (5, 2): "Redirect Datagram for the Type of Service and Network",
    (5, 3): "Redirect Datagram for the Type of Service and Host",
    (7, 0): "Unassigned",
    (8, 0): "Echo",
    (11, 0): "Time to Live exceeded in Transit",
    (11, 1): "Fragment Reassembly Time Exceeded",
}
