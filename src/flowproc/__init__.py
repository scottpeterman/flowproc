# -*- coding: utf-8 -*-

"""
tbd
"""

import logging

from pkg_resources import DistributionNotFound
from pkg_resources import get_distribution

# from flowproc import ipfix
from flowproc import netflowV5
from flowproc import netflowV9
from flowproc import util

__author__ = "Tobias Frei"
__copyright__ = "Tobias Frei"
__license__ = "mit"

logger = logging.getLogger(__name__)

# retrieve version info
try:
    dist_name = __name__
    __version__ = get_distribution(dist_name).version
except DistributionNotFound:
    __version__ = "unknown"
finally:
    del get_distribution, DistributionNotFound


def process(client_addr, export_packet, Writer):
    """A high level function to collect export packets from NetFlow
    versions 5, 9 and IPFIX.
    Args:
        client_addr     `str`   client ip address
        export_packet   `bytes` export packet received
        Writer          `flowproc.Writer` instance to process results
                        (obsolete before birth :| - replace by fluent API!)
    """

    # TODO design and implement output processing chain/ workflow

    v5 = netflowV5.Collector(
        [
            "sIP",
            "dIP",
            "packets",
            "bytes",
            # "sTime",
            # "eTime",
            "sPort",
            "dPort",
            "flags",
            "protocol",
        ]
    )

    ver = util.get_header_version(export_packet)

    if ver == 5:
        func = v5.collect
    elif ver == 9:
        func = netflowV9.collpack
    else:
        # Raise an exception but continue processing for correct packets.
        raise UnknownVersion(ver)

    # call suitable collector
    func(client_addr, export_packet)


class UnknownVersion(KeyError):
    """Show the version refused."""

    def __init__(self, val):
        super(UnknownVersion, self).__init__(val)
