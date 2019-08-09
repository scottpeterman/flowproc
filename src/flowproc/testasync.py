# -*- coding: utf-8 -*-
"""
Experimental
"""

import json
import logging

from datetime import datetime

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
    Return collector state nested in JSON format
    """

    @stopwatch
    def visit_Collector(self, host):
        collector = {
            "flowproc": __version__,
            "at": str(datetime.utcnow()),  # TODO add timezone info
            "parser": "V9 someting...",
            # "transport": "UDP",
            # "security": None,
        }
        exp = {}
        collector["exporters"] = exp

        for child in host.children.values():
            exp[child.ipa] = []
            exp[child.ipa].append(child.accept(self))

        return json.dumps(collector, indent=4)
        # return str(self.collector)

    def visit_Exporter(self, host):
        domain = {}

        for child in host.children.values():
            attr = {}
            domain[child.odid] = attr
            attr["optstrings"] = [str(opt) for opt in child.optrecs]
            attr["templatestrings"] = [
                template for template in child.accept(self)
            ]

        return domain

    def visit_ObservationDomain(self, host):
        strings = []
        for child in host.children.values():
            # template classes' __str__ method for this short JSON document
            strings.append(str(child))

        return strings


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
