# -*- coding: utf-8 -*-
"""
Highly EXPERIMENTAL!
"""

import logging

from flowproc.collector_state import Collector

__author__ = "Tobias Frei"
__copyright__ = "Tobias Frei"
__license__ = "mit"

# globals
logger = logging.getLogger(__name__)


class TreeVisitor:
    """
    Return some kind of ASCII tree
    """

    def visit_Collector(self, host):
        for child in host.children.values():
            yield str(child) + "\n"
            child.accept(self)

    def visit_Exporter(self, host):
        for child in host.children.values():
            yield "\t" + str(child) + "\n"
            child.accept(self)

    def visit_ObservationDomain(self, host):
        for child in host.children.values():
            yield "\t" * 2 + str(child) + "\n"


def depth_first_iter():
    """
    Return some kind of ASCII tree
    """
    rep = ''
    yield rep
    for exp in Collector.children.values():
        rep += str(exp) + "\n"

        for od in exp.children.values():
            rep += "\t" + str(child) + "\n"

            for template in od.children.values():
                rep += "\t" * 2 + str(child) + "\n"
