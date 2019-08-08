# -*- coding: utf-8 -*-
"""
Highly EXPERIMENTAL!
"""

import json
import logging

from flowproc import __version__
from flowproc.collector_state import Collector
from flowproc.util import stopwatch

__author__ = "Tobias Frei"
__copyright__ = "Tobias Frei"
__license__ = "mit"

# globals
logger = logging.getLogger(__name__)


class TreeVisitor:
    """
    Return some kind of ASCII tree
    """

    def __init__(self):
        self.rep = Collector.__name__ + "\n"

    @stopwatch
    def visit_Collector(self, host):
        for child in host.children.values():
            self.rep += str(child) + "\n"
            child.accept(self)
            return self.rep

    def visit_Exporter(self, host):
        for child in host.children.values():
            self.rep += "\t" + str(child) + "\n"
            child.accept(self)

    def visit_ObservationDomain(self, host):
        for child in host.children.values():
            self.rep += "\t" * 2 + str(child) + "\n"


@stopwatch
def depth_first_iter():
    """
    Return some kind of ASCII tree
    """
    rep = str(Collector) + "\n"
    for exp in Collector.children.values():
        rep += str(exp) + "\n"

        for od in exp.children.values():
            rep += "\t" + str(od) + "\n"

            for template in od.children.values():
                rep += str(template) + "\n"
    return rep


def stats():
    """
    Print basic statistics
    """
    return """Collector version: {}
Collector started: {}

Packets processed:    {:9d}
Headers record count: {:9d}
Records processed:    {:9d}
Records diff:         {:9d}""".format(
        __version__,
        Collector.created,
        Collector.packets,
        Collector.count,
        Collector.record_count,
        Collector.count - Collector.record_count,
    )
