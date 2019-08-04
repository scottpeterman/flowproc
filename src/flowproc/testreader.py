#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
A helper program to read binary NetFlow V5, V9 and IPFIX export packets from
disk and feed these to collectors
"""

import argparse
import logging
import struct
import sys

from datetime import datetime

from flowproc.netflow_v5 import Collector as Cv5
from flowproc.netflow_v9 import Collector as Cv9

from flowproc import __version__

# assign functions
unpack_hdr5 = Cv5.unpack_header
unpack_hdr9 = Cv9.unpack_header

__author__ = "Tobias Frei"
__copyright__ = "Tobias Frei"
__license__ = "mit"

# globals
expected = None
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
logger.addHandler(logging.StreamHandler())


def feed_5(fp, stat=False, selection=None):
    """stat: print statistics only"""

    # New collector with all fields from packets
    C = Cv5("all")
    _read = 0  # export packets read (used for selection)

    # for stat
    start_date = None
    end_date = None
    packets = 0
    records = 0
    min_recs = 30
    max_recs = 0
    domains = set()
    seq_err = {}

    fmt = "!HHIIIIBBH"
    while True:
        bin_hdr = fp.read(24)
        if len(bin_hdr) < 24:
            break  # EOF

        hdr = struct.unpack(fmt, bin_hdr)
        counter = hdr[1]

        data = fp.read(counter * 48)  # 48: NetFlow V5 rec length
        if selection:
            _read += 1
            if _read < selection[1]:
                continue
            if sum(selection) - 1 < _read:
                continue

        # call collector
        if not stat:
            C.collect("0.0.0.0", bin_hdr + data)

        else:
            records += counter
            packets += 1
            min_recs = min(counter, min_recs)
            max_recs = max(counter, max_recs)
            domains.add(hdr[7])

            if not start_date:
                start_date = hdr[3]
            if not end_date:
                end_date = hdr[3]

            # check sequence
            global expected
            if expected:
                if not hdr[5] == expected:
                    seq_err[packets] = {"actual": hdr[5], "expected": expected}
            expected = hdr[5] + counter

    # stat
    if stat:
        sdt = datetime.fromtimestamp(start_date)
        edt = datetime.fromtimestamp(end_date)
        print("Start:     ", sdt)
        print("End:       ", edt)
        print("Observation domains:  ", domains)
        print("Packets: {} records: {}".format(packets, records))
        print("avg records in packet:", round(records / packets, 1))
        print("min records in packet:", min_recs)
        print("max records in packet:", max_recs)
        print("Sequence errors:")

        for k, v in seq_err.items():
            print("{:6d} {}".format(k, v))


def feed_9(fp):
    """This IS EXPERIMENTAL !!"""

    fmt = "!HHIIII"

    def _is_header(header):
        """Return True if this looks like a Netflow V9 header"""

        # TODO improve criteria as only lowest few Source IDs won't do
        #      for some people.
        if header[0] == 9 and header[-1] in (0, 1, 2, 3, 4):
            return True
        else:
            return False

    def _find_header():
        """Find the next good-looking candidate"""
        WORD = 4

        pos = fp.tell()
        mod = pos % WORD
        if mod != 0:
            fp.read(WORD - mod)  # aligned to boundary

        pos = fp.tell()
        while True:
            header = struct.unpack(fmt, fp.read(20))
            if _is_header(header):
                fp.seek(pos)  # back to start of this header
                return header
            else:
                fp.read(WORD)

    while True:
        header = struct.unpack(fmt, fp.read(20))
        if not _is_header(header):
            header = _find_header()

        pos = fp.tell()
        print("{:5d} Found export packet header: {}".format(pos, header))


        while True:  # More robust than the next 2 lines, there is a 'Count' problem!
        # counter = header[1]
        # for i in range(counter):
            # Inspect Data- Template- and Data Template Flow Sets
            pos = fp.tell()
            set_id, length = struct.unpack("!HH", fp.read(4))
            print(
                "{:5d}   Flow Set id: {:3d} length: {:d}".format(
                    pos, set_id, length
                )
            )

            # to next set
            try:
                fp.read(length - 4)
            except ValueError as e:
                pos = fp.tell()
                print("{:5d}   {} ...skipping".format(pos, e))
                _find_header()  # don't fuss, skip to next
                break


def ipfeed(fp):
    print("10 notimpl")


def parse_args(args):
    """Parse command line parameters

    Args:
      args ([str]): command line parameters as list of strings

    Returns:
      :obj:`argparse.Namespace`: command line parameters namespace
    """
    parser = argparse.ArgumentParser(
        description="""A helper program to read binary NetFlow V5, V9 and
        IPFIX export packets from disk and feed these to collectors""",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("-i", "--infile", required=True, metavar="path")
    parser.add_argument(
        "-r",
        "--range",
        nargs=2,
        type=int,
        default=None,
        help="RANGE START_PACKET, when `None` read all",
    )
    parser.add_argument(
        "-s",
        "--summary",
        help="print file summary instead of calling collector",
        action="store_true",
    )
    parser.add_argument(
        "-V",
        "--version",
        help="print packet version and exit",
        action="version",
        version="flowproc {ver}".format(ver=__version__),
    )

    # TODO add options to select output processing

    return parser.parse_args(args)


def main(args):
    """Main entry point allowing external calls

    Args:
      args ([str]): command line parameter list
    """
    args = parse_args(args)
    print("Args {}".format(vars(args)))

    with open(args.infile, "rb") as fp:
        ver = struct.unpack("!H", fp.read(2))[0]

        if ver in (5, 9):
            print("{} looks like NetFlow V{}".format(args.infile, ver))
        elif ver == 10:
            print("{} looks like IPFIX".format(args.infile))
        else:
            print("Fishy file format... ¯\\_(°.°)_/¯")

        fp.seek(0)  # reset before starting for real

        if ver == 5:
            feed_5(fp, stat=args.summary, selection=args.range)
        elif ver == 9:
            feed_9(fp)
            # _walk_4(fp)
        else:
            ipfeed(fp)


def run():
    """Entry point for console_scripts
    """
    main(sys.argv[1:])


if __name__ == "__main__":
    run()
