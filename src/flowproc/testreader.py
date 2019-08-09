#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Test parsers using raw NetFlow/IPFIX input from disk
"""

import argparse
import struct
import sys
import logging

from flowproc import __version__
from flowproc import testasync
# from flowproc import v5_parser
from flowproc import v9_parser

# from flowproc import v10_parser

__author__ = "Tobias Frei"
__copyright__ = "Tobias Frei"
__license__ = "mit"

# global settings
logger = logging.getLogger()  # root
fmt = logging.Formatter("%(levelname)-8s %(name)s: %(message)s")
sh = logging.StreamHandler(sys.stderr)
sh.setFormatter(fmt)
# logger.setLevel(logging.DEBUG)
logger.addHandler(sh)


def parse_args(args):
    """Parse command line parameters

    Args:
      args ([str]): command line parameters as list of strings

    Returns:
      :obj:`argparse.Namespace`: command line parameters namespace
    """
    parser = argparse.ArgumentParser(
        description="Test parsers using raw NetFlow/IPFIX input from disk"
    )
    parser.add_argument(
        "-V",
        action="version",
        version="flowproc {ver}".format(ver=__version__),
    )
    parser.add_argument(
        dest="infile", help="input file to use", type=str, metavar="INPUT_FILE"
    )
    parser.add_argument(
        "-d",
        dest="loglevel",
        help="set loglevel to DEBUG",
        action="store_const",
        const=logging.DEBUG,
    )
    parser.add_argument(
        "-i",
        dest="loglevel",
        help="set loglevel to INFO",
        action="store_const",
        const=logging.INFO,
    )
    parser.add_argument(
        "-w",
        "--verbose",
        dest="loglevel",
        help="set loglevel to WARNING (default)",
        action="store_const",
        const=logging.WARNING,
    )
    parser.add_argument(
        "-e",
        dest="loglevel",
        help="set loglevel to ERROR",
        action="store_const",
        const=logging.ERROR,
    )
    return parser.parse_args(args)


def main(args):
    """Main entry point allowing external calls

    Args:
      args ([str]): command line parameter list
    """
    args = parse_args(args)
    logger.setLevel(logging.WARNING) if not args.loglevel else logger.setLevel(
        args.loglevel
    )

    try:
        with open(args.infile, "rb") as fh:
            ver = struct.unpack("!H", fh.read(2))[0]
            fh.seek(0)  # reset

            if ver == 9:
                v9_parser.parse_file(fh, "0.0.0.0")
            else:
                print(
                    "Not equipped to parse ver {:d}, giving up...".format(ver)
                )
    except KeyboardInterrupt:
        print()  # newline
        print("Closing infile...")

    print(testasync.stats())


def run():
    """
    Entry point for console_scripts
    """
    main(sys.argv[1:])


if __name__ == "__main__":
    run()
