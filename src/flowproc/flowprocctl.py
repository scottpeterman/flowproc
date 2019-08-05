#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
The flow collector daemon control program
"""

import argparse
import socket
import sys
import logging

from flowproc import __version__

__author__ = "Tobias Frei"
__copyright__ = "Tobias Frei"
__license__ = "mit"


def parse_args(args):
    """
    Parse command line parameters
    """
    parser = argparse.ArgumentParser(
        description="Communicate with testlistener over UNIX socket"
    )
    parser.add_argument(
        dest="cmd",
        help="ping, stats",
        type=str,
        metavar="command"
    )
    parser.add_argument(
        "-s",
        "--sock",
        help="unix socket path for control",
        type=str,
        action="store",
    )
    parser.add_argument(
        "-V",
        action="version",
        version="flowproc {ver}".format(ver=__version__),
    )
    return parser.parse_args(args)


def main(args):
    """
    Main entry point allowing external calls
    """
    args = parse_args(args)

    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.connect(args.sock)
    TX = args.cmd.encode()
    TX_sent = client.send(TX)

    if TX_sent != len(TX):
        print("TX incomplete")

    print(client.recv(1024).decode())
    client.close()


def run():
    """Entry point for console_scripts
    """
    main(sys.argv[1:])


if __name__ == "__main__":
    run()
