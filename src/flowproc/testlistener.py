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

from importlib import reload

from flowproc import __version__
from flowproc import testasync
# from flowproc import v5_parser
from flowproc import v9_classes
from flowproc import v9_fieldtypes
from flowproc import v9_parser
# from flowproc import v10_parser
from flowproc.collector_state import Collector

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


def start(parser, host, port, socketpath):
    """
    Fire up an asyncio event loop
    """

    class NetFlow:  # the protocol definition
        def connection_made(self, transport):
            self.transport = transport

        def datagram_received(self, datagram, addr):
            parser.parse_packet(datagram, addr[0])

        def connection_lost(self, exc):
            pass

    @asyncio.coroutine
    def callback(reader, writer):  # callback function for Unix Sockets
        data = yield from reader.read(1024)
        msg = data.decode()
        msg = run_command(msg)
        writer.write(msg.encode())
        yield from writer.drain()
        writer.close()

    def load():
        modules = (testasync, v9_classes, v9_fieldtypes)
        [reload(m) for m in modules]
        logger.info("Reloaded {}".format(modules))
        return "reloaded {}".format([m.__name__ for m in modules])

    def stop():
        loop.stop()
        return "stopping event loop..."

    def run_command(cmd):
        """
        Reply to the few commands existing
        """
        run = {
            "ping": lambda: "pong",
            "stats": testasync.stats,
            "tree": testasync.depth_first_iter,
            "visit": lambda: Collector.accept(testasync.TreeVisitor()),
            "reload": lambda: load(),
            "shutdown": stop,
            "help": lambda: "Command must be one of {}".format(
                [c for c in run.keys()]
            ),
        }
        if cmd not in run.keys():
            return "Command '{}' unknown".format(cmd)
        else:
            return run[cmd]()

    loop = asyncio.get_event_loop()
    # UDP
    logger.info("Starting UDP server on host {} port {}".format(host, port))
    coro = loop.create_datagram_endpoint(NetFlow, local_addr=(host, port))
    transport, protocol = loop.run_until_complete(coro)
    # Unix Sockets (ctrl)
    if socketpath:
        logger.info("Starting Unix Socket on {}".format(socketpath))
        coro = asyncio.start_unix_server(callback, socketpath, loop=loop)
        socketserver = loop.run_until_complete(coro)
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        print()  # newline for ^C

    logger.info("Shutting down...")
    transport.close()
    if socketpath:
        socketserver.close()
        os.remove(socketpath)
    loop.close()


def main(args):
    """
    Main entry point allowing external calls
    """
    parser = None
    port = None

    args = parse_args(args)
    logger.setLevel(logging.WARNING) if not args.loglevel else logger.setLevel(
        args.loglevel
    )
    logger.debug(args)

    # configure
    socketpath = args.sock

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

    # fire up event loop
    start(parser, "0.0.0.0", port, socketpath)


def run():
    """
    Entry point for console_scripts
    """
    main(sys.argv[1:])


if __name__ == "__main__":
    run()
