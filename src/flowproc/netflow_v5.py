# -*- coding: utf-8 -*-

"""
NetFlow v5 collector implementation
"""

import logging
import struct

from collections import namedtuple
from datetime import datetime
from flowproc import util
from ipaddress import ip_address

__author__ = "Tobias Frei"
__copyright__ = "Tobias Frei"
__license__ = "mit"

# global
logger = logging.getLogger(__name__)
RECORD_LENGTH = 48


class Collector(util.AbstractCollector):

    STRUCT_NFV5 = {
        "srcaddr": (0, 4, "I"),
        "dstaddr": (4, 4, "I"),
        "nexthop": (8, 4, "I"),
        "input": (12, 2, "H"),
        "output": (14, 2, "H"),
        "dPkts": (16, 4, "I"),
        "dOctets": (20, 4, "I"),
        "First": (24, 4, "I"),
        "Last": (28, 4, "I"),
        "srcport": (32, 2, "H"),
        "dstport": (34, 2, "H"),
        "pad1": (36, 1, "x"),
        "tcp_flags": (37, 1, "B"),
        "prot": (38, 1, "B"),
        "tos": (39, 1, "B"),
        "src_as": (40, 2, "H"),
        "dst_as": (42, 2, "H"),
        "src_mask": (44, 1, "B"),
        "dst_mask": (45, 1, "B"),
        "pad2": (46, 2, "x"),
    }

    SILK_TO_NFV5 = {
        "sIP": "srcaddr",
        "dIP": "dstaddr",
        "nhIP": "nexthop",
        "inNic": "input",  # altered from 'in' for clarification
        "outNic": "output",  # altered from 'out' for clarification
        "packets": "dPkts",
        "bytes": "dOctets",
        "sTime": "First",
        "eTime": "Last",
        "sPort": "srcport",
        "dPort": "dstport",
        "flags": "tcp_flags",
        "protocol": "prot",
        "tos": "tos",  # not SiLK-like
        "sASN": "src_as",  # not SiLK-like
        "dASN": "dst_as",  # not SiLK-like
    }

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

    def __init__(self, fields):
        """
        Args:
            fields      either "all" or a subset of keys in SILK_TO_NFV5
        """

        # FIXME When fields not enumerated in sequential order given by struct,
        #       they DO label the wrong fields (i.e. values)!

        self.fields = (
            [k for k in Collector.SILK_TO_NFV5.keys()]
            if fields == "all"
            else fields
        )

        # format string for `struct.unpack`
        self.format_string = Collector._compose_format(self.fields)

        # transform_pretty for now
        self.TRANSFORM_NFV5 = {
            "sIP": lambda x: str(ip_address(x)),
            "dIP": lambda x: str(ip_address(x)),
            "nhIP": lambda x: str(ip_address(x)),
            "inNic": lambda x: x,
            "outNic": lambda x: x,
            "packets": lambda x: x,
            "bytes": lambda x: x,
            "sTime": lambda x: self._abs_time(x),
            "eTime": lambda x: self._abs_time(x),
            "sPort": lambda x: util.port_to_str(x),
            "dPort": lambda x: util.port_to_str(x),
            "flags": lambda x: util.tcpflags_h(x, brief=False),
            "protocol": lambda x: util.proto_to_str(x),
            "tos": lambda x: x,
            "sASN": lambda x: x,
            "dASN": lambda x: x,
        }

        # list of functions for transforming unpacked structure
        self.xform_list = [
            func for k, func in self.TRANSFORM_NFV5.items() if k in self.fields
        ]

        # named tuple for flow records to return
        self.FlowRec = namedtuple("FlowRec", self.fields)

    def __repr__(self):
        return str(self.fields)

    @staticmethod
    def _unpack_header(packet):

        # header contents as enumerated in
        # https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html#wp1006108
        contents = [
            "version",
            "count",
            "SysUptime",
            "unix_secs",
            "unix_nsecs",
            "flow_sequence",
            "engine_type",
            "engine_id",
            "sampling_interval",
        ]
        unpacked = struct.unpack("!HHIIIIBBH", packet[:24])

        assert len(contents) == len(unpacked)
        return dict(zip(contents, unpacked))

    def collect(self, client_addr, export_packet):
        """See `flowproc.util.AbstractCollector.collect`"""

        # entry level test
        ver = util.get_header_version(export_packet)
        if ver != 5:
            logger.error("Cannot process header version {}".format(ver))
            return

        # get header
        header = Collector._unpack_header(export_packet)

        # log export packet summary
        logger.debug(
            "Received {:4d} bytes from observation dom {:d} at {}".format(
                len(export_packet), header["engine_id"], client_addr
            )
        )

        # prepare variables for record processing
        counter = header["count"]
        self.exporter_start_t = (
            header["unix_secs"]
            + round(header["unix_nsecs"] / 10 ** 6, 3)
            - header["SysUptime"] / 1000
        )
        logger.debug(
            "Exporter started on {}".format(
                datetime.fromtimestamp(self.exporter_start_t).strftime(
                    "%b %m %Y %H:%M:%S"
                )
            )
        )

        flowrec_iterable = []

        # loop over records
        data_offset = 24
        for i in range(counter):
            ptr = data_offset + i * RECORD_LENGTH
            record = export_packet[ptr : ptr + RECORD_LENGTH]

            unpacked = struct.unpack(self.format_string, record)
            transformed = list(
                map(lambda f, y: f(y), self.xform_list, unpacked)
            )
            flowrec = self.FlowRec(*transformed)

            flowrec_iterable.append(flowrec)

        for rec in flowrec_iterable:
            # For now just print every single record, prefixed with
            # observation domain attributes.
            print((client_addr, header["engine_id"]), rec)

    # methods to be moved to prettyfiers

    def _abs_time(self, rel_t):
        return datetime.fromtimestamp(
            self.exporter_start_t + rel_t / 1000
        ).strftime("%b %m %Y %H:%M:%S.%f")
