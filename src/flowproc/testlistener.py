#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Test UDP listener
"""

import argparse
import asyncio
import sys
import logging
import os

from flowproc import __version__

# from flowproc import v5_parser
from flowproc import v9_parser

# from flowproc import v10_parser
from flowproc.collector_state import Collector
from flowproc.testasync import depth_first_iter

__author__ = "Tobias Frei"
__copyright__ = "Tobias Frei"
__license__ = "mit"

# global settings
logger = logging.getLogger()  # root
fmt = logging.Formatter("[%(asctime)s] %(levelname)-8s %(name)s: %(message)s")
sh = logging.StreamHandler(sys.stderr)
sh.setFormatter(fmt)
logger.addHandler(sh)


def parse_args(args):
    """
    Parse command line parameters
    """
    parser = argparse.ArgumentParser(
        description="Test parsers with UDP packets coming in"
    )
    parser.add_argument(
        dest="parser",
        help="set parser to use (values are: 'v5', 'v9' or 'ipfix'",
        type=str,
    )
    parser.add_argument(
        "-p",
        "--port",
        help="set port to listen on (defaults: NetFlow 2055, IPFIX 4739)",
        type=int,
        action="store",
    )
    parser.add_argument(
        "-s",
        "--sock",
        help="unix socket path for control",
        type=str,
        action="store",
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
    parser.add_argument(
        "-V",
        action="version",
        version="flowproc {ver}".format(ver=__version__),
    )
    return parser.parse_args(args)


def stats():
    """
    Print basic statistics
    """
    return """Collector version: {}
Collector started: {}
Packets processed:    {:9d}
Headers record count: {:9d}
Records processed:    {:9d}""".format(
        __version__,
        Collector.created,
        Collector.packets,
        Collector.count,
        Collector.record_count,
    )


def startup(parser, port, socketpath):
    """
    Fire up an asyncio event loop
    """

    class FlowServerProtocol:
        def connection_made(self, transport):
            self.transport = transport

        def datagram_received(self, datagram, addr):
            parser.parse_packet(datagram, addr[0])

        def connection_lost(self, exc):
            pass

    def stop():
        loop.stop()

    def run_command(cmd):
        """
        Reply to the few commands existing
        """
        run = {
            "ping": lambda: "pong",
            "stats": stats,
            "tree": depth_first_iter,
            "shutdown": stop,
            "help": lambda: "Command must be one of {}".format(
                [c for c in run.keys()]
            ),
        }
        if cmd not in run.keys():
            return "Command '{}' unknown".format(cmd)
        else:
            return run[cmd]()

    class CtrlServerProtocol:
        def connection_made(self, transport):
            self.transport = transport

        def data_received(self, data):
            reply = run_command(data.decode())
            try:
                self.transport.write(reply.encode())
            except AttributeError:  # occurs when shutting down from here
                pass

        def connection_lost(self, exc):
            pass

        def eof_received(self):
            pass

    loop = asyncio.get_event_loop()

    # UDP server
    coro = loop.create_datagram_endpoint(
        FlowServerProtocol, local_addr=("0.0.0.0", port)
    )
    logger.info("Creating UDP server, host 0.0.0.0, port {:d}".format(port))
    transport, protocol = loop.run_until_complete(coro)

    # Unix socket server (ctrl)
    if socketpath:
        coro = loop.create_unix_server(CtrlServerProtocol, path=socketpath)
        logger.info(
            "Creating Unix domain socket server on '{}'".format(socketpath)
        )
        sockserver = loop.run_until_complete(coro)

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        print()  # newline for ^C

    logger.info("Shutting down...")
    transport.close()
    if socketpath:
        sockserver.close()
        os.remove(socketpath)
    loop.close()


def main(args):
    """
    Main entry point allowing external calls
    """
    parser = None
    port = None
    sock = None

    args = parse_args(args)
    logger.setLevel(logging.WARNING) if not args.loglevel else logger.setLevel(
        args.loglevel
    )
    logger.debug(args)

    # configure
    sock = args.sock

    if args.parser.lower() == "v5":
        # parser = v9_parser
        port = 2055 if not args.port else args.port
    elif args.parser.lower() == "v9":
        parser = v9_parser
        port = 2055 if not args.port else args.port
    elif args.parser.lower() == "ipfix":
        # parser = ipfix_parser
        port = 4739 if not args.port else args.port

    if not parser:
        print("No suitable parser configured, giving up...")
        exit(1)

    logger.debug(
        "Starting with parser={}, port={:d}, sock={}".format(
            parser.__name__, port, sock
        )
    )

    # fire up event loop
    startup(parser, port, sock)


def run():
    """
    Entry point for console_scripts
    """
    main(sys.argv[1:])


if __name__ == "__main__":
    run()
