# -*- coding: utf-8 -*-
"""
Tests for 'util' module
"""

__author__ = "Tobias Frei"
__copyright__ = "Tobias Frei"
__license__ = "mit"

import logging
import time

from datetime import datetime

from flowproc import testasync
from flowproc.collector_state import AbstractTemplate
from flowproc.collector_state import Collector

# globals
logger = logging.getLogger().setLevel(logging.DEBUG)


class T(AbstractTemplate):
    """
    Helper template class for testing
    """

    def __init__(self, tid):
        self.tid = tid
        # some simulation of real-life attrs
        self.attr = list(map(lambda x: self.tid * x, [18, 22, 0.77, 3, 5]))
        self.lastwrite = datetime.utcnow()

    def get_tid(self):
        return self.tid

    def __str__(self):
        return str("T({}, {})".format(self.tid, self.lastwrite))

    def __repr__(self):
        return str("T({}, {})".format(self.tid, self.attr))


# register some objects before testing
Collector.register("127.0.0.1", 0, T(300))
Collector.register("127.0.0.1", 0, T(387))
Collector.register("127.0.0.1", 1, T(387))
Collector.register("2001:420:1101:1::185", 0, T(326))
Collector.register("8.8.4.4", 3, T(300))

time.sleep(0.3)  # updated template example:
Collector.register("127.0.0.1", 0, T(300))


def test_Collector_get():

    # empty path
    assert Collector.get_qualified().__name__ == "Collector"

    # paths with ipa (ip address) only
    assert str(Collector.get_qualified("127.0.0.1")) == "127.0.0.1"  # existent
    assert str(Collector.get_qualified("8.8.4.4")) == "8.8.4.4"  # existent
    assert (
        str(Collector.get_qualified("2001:420:1101:1::185"))
        == "2001:0420:1101:0001:0000:0000:0000:0185"
    )
    assert Collector.get_qualified("8.8.8.8") is None  # missing

    # paths ipa, odid (observation domain ID)
    assert str(Collector.get_qualified("2001:420:1101:1::185", 0)) == "0"
    assert (
        Collector.get_qualified("2001:420:1101:1::186", 0) is None
    )  # missing
    assert (
        Collector.get_qualified("2001:420:1101:1::185", 1) is None
    )  # missing

    # paths ipa, odid, tid (Template ID)
    assert Collector.get_qualified("127.0.0.1", 0, 300).get_tid() == 300
    assert Collector.get_qualified("127.0.0.1", 1, 300) is None  # missing)
    assert Collector.get_qualified("127.0.0.1", 0, 301) is None  # missing)

    # see if the rest above has been registered
    assert None not in (
        Collector.get_qualified("127.0.0.1", 0),
        Collector.get_qualified("127.0.0.1", 1),
        Collector.get_qualified("127.0.0.1", 0, 387),
        Collector.get_qualified("127.0.0.1", 1, 387),
        Collector.get_qualified("8.8.4.4", 3),
        Collector.get_qualified("2001:420:1101:1::185", 0, 326),
        Collector.get_qualified("8.8.4.4", 3, 300),
    )

    # TODO Collector.check_header()
    # TODO Collector.unregister()


def test_Collector_register_optrec():

    rec = {
        "System": 2130706433,
        "INPUT_SNMP": 128,
        "IF_NAME": "lo",
        "IF_DESC": "Loopback",
    }
    # path not existing: False
    assert not Collector.register_optrec("127.0.0.1", 2, rec)

    # existing: True
    assert Collector.register_optrec("127.0.0.1", 1, rec)

    print(Collector.accept(testasync.TreeVisitor()))
