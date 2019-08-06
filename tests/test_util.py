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
    flags = util.tcpflags_to_str(17)
    assert "fin" in flags
    assert "ack" in flags


def test_proto():
    assert util.PROTO[132] == "SCTP"


def test_to_icmptc():
    assert util.dstport_to_icmptc(769) == (3, 1,)  # host unreachable
