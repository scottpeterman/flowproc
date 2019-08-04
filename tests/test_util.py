# -*- coding: utf-8 -*-
"""
Tests for 'util' module
"""

__author__ = "Tobias Frei"
__copyright__ = "Tobias Frei"
__license__ = "mit"

import logging

from flowproc import util

# globals
logger = logging.getLogger().setLevel(logging.DEBUG)


@util.stopwatch
def test_watch():
    pass


def test_port():
    assert util.port_to_str(443) == "https"


def test_tcpflags():
    assert util.tcpflags_to_str(17) == ["fin", "ack"]


def test_proto():
    assert util.PROTO[132] == "SCTP"


def test_to_icmptc():
    assert util.dstport_to_icmptc(769) == (3, 1,)  # host unreachable


def test_Exporter():
    # test __init__ and __repr__
    assert str(util.Exporter(167772161, 0)) == "Exporter(10.0.0.1, 0)"
    assert str(util.Exporter("10.0.0.1", 0)) == "Exporter(10.0.0.1, 0)"
