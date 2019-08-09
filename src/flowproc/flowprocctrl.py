#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
The flow collector daemon control program
"""

import argparse
import asyncio
import json
import pprint
import sys

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


@asyncio.coroutine
def unix_socket_client(command, socketpath):
    reader, writer = yield from asyncio.open_unix_connection(socketpath)

    # command += "\n"  # readline() in the other end!
    # read(1024) on the other end
    writer.write(command.encode())

    data = yield from reader.read(-1)

    msg = data.decode()
    # If JSON, we might pretty-print:
    try:
        msg = json.loads(msg)
        # pprint.PrettyPrinter(indent=1, width=80, compact=True)
        pprint.pprint(msg, width=172, compact=True)
    except json.decoder.JSONDecodeError:
        print(msg)

    writer.close()


def main(args):
    """
    Main entry point allowing external calls
    """
    args = parse_args(args)

    loop = asyncio.get_event_loop()
    loop.run_until_complete(unix_socket_client(args.cmd, args.sock))
    loop.close()


def run():
    """
    Entry point for console_scripts
    """
    main(sys.argv[1:])


if __name__ == "__main__":
    run()
