# -*- coding: utf-8 -*-

"""
NetFlow V9 collector implementation
"""

import logging
import struct

from collections import namedtuple
from flowproc import util

__author__ = "Tobias Frei"
__copyright__ = "Tobias Frei"
__license__ = "mit"

# global
logger = logging.getLogger(__name__)


class Collector(util.AbstractCollector):
    def __repr__(self):
        return "TODO"

    @classmethod
    def _compose_format(cls, fields):
        # Translate (SiLKy) fields to list of NetFlow v5 field labels.
        selection = [v for k, v in cls.SILK_TO_NFV5.items() if k in fields]

        format_string = "!"  # starting with network big endian

        for k, v in cls.STRUCT_NFV5.items():
            if k in selection:
                # Append format character for field.
                format_string += v[2]
            else:
                # Add number of padding characters required to skip
                # unwanted field.
                format_string += v[1] * "x"

        return format_string

    def __init__(self):
        """TODO
        """
        self.previous = None  # to store previous export packet seq_no

    def _sequence_check(self, seq_no):
        if self.previous:
            if self.previous + 1 != seq_no:
                logger.error(
                    "seq_no expected {d} but got {d}".format(
                        self.previous + 1, seq_no
                    )
                )
                self.previous = seq_no
            else:
                self.previous += 1

    @staticmethod
    def unpack_header(packet):
        """header length: 20"""

        # RFC 3954 5.1.
        contents = [
            "Version Number",
            "Count",
            "sysUpTime",
            "UNIX Secs",
            "Sequence Number",
            "Source ID",
        ]
        unpacked = struct.unpack("!HHIIII", packet[:20])

        # assert len(contents) == len(unpacked)
        return dict(zip(contents, unpacked))

    def collect(self, client_addr, export_packet):
        """See `flowproc.util.AbstractCollector.collect`"""

        # entry level test
        ver = util.get_header_version(export_packet)
        if ver != 9:
            logger.error("Cannot process header version {}".format(ver))
            return

        # get header
        header = Collector.unpack_header(export_packet)

        # sequence check
        self._sequence_check(header["Sequence Number"])

        # log export packet summary
        logger.debug(
            "Received {:4d} bytes from observation domain {:d} at {}".format(
                len(export_packet), header["Source ID"], client_addr
            )
        )

        # See what kind of set we got:
        #
        # Template FlowSet ... blah
        #
        print(header)
        counter = header["Count"]
        pos = 20

        for i in range(counter):
            # Inspect set Id and length
            fsid, length = struct.unpack("!HH", export_packet[pos : pos + 4])
            print(
                "FlowSetID {:3d} @ {:4d} with length {:4d} (i={}/{})".format(
                    fsid, pos, length, i, counter
                )
            )
            pos += length
