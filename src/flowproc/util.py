# -*- coding: utf-8 -*-

"""
Utility functions for flow processing
"""

# import logging
import socket
import struct

from abc import ABC
from abc import abstractmethod

__author__ = "Tobias Frei"
__copyright__ = "Tobias Frei"
__license__ = "mit"

# logger = logging.getLogger(__name__)


def get_header_version(packet):
    """Unpack and return the packet header version number.
    """
    unpacked = struct.unpack("!H", packet[:2])  # 2 bytes, network big endian
    return unpacked[0]


def port_to_str(port):
    """TODO
    """
    try:
        return socket.getservbyport(port)
    except OSError:
        return port


def proto_to_str(proto):
    """TODO
    """
    if proto == 1:
        return "ICMP"
    elif proto == 6:
        return "TCP"
    elif proto == 17:
        return "UDP"
    else:
        return proto
    # TODO Add the rest! Is there a more elegant way to resolve these?


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


def tcpflags_h(flags, brief=True):
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


# TODO To be moved for integration with fluent API?
class AbstractCollector(ABC):

    @abstractmethod
    def __repr__(self):
        pass

    @abstractmethod
    def collect(self, client_addr, export_packet):
        """Collect export packet.
        Args:
            client_addr     `str`   client ip address
            export_packet   `bytes` export packet received
        Return:
            iterable over `collections.namedtuple`
        """
        pass
