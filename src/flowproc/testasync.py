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
from flowproc.v9_classes import OptionsTemplate
from flowproc.v9_classes import Template
from flowproc import v9_fieldtypes

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

        # return as is, pretty-printing to be done on client side
        return json.dumps(collector)

    def visit_Exporter(self, host):
        domain = {}

        for child in host.children.values():
            attr = {}
            domain[child.odid] = attr
            attr["options_records"] = [rec for rec in child.optrecs if rec is not None]
            attr["templates"] = child.accept(self)

        return domain

    def visit_ObservationDomain(self, host):
        templates = {}
        for child in host.children.values():
            attr = {}
            templates[child.tid] = attr
            # Format returned by str( timedelta ) e.g '0:02:41.411545' -
            # we just show the first part and discard fractions of seconds.
            attr["age"] = str(datetime.utcnow() - child.lastwrite).split(".")[
                0
            ]
            if isinstance(child, Template):
                attr["types"] = [
                    v9_fieldtypes.LABEL.get(n, n) for n in child.types
                ]
            if isinstance(child, OptionsTemplate):
                attr["scope_types"] = [
                    v9_fieldtypes.SCOPE_LABEL.get(n, n)
                    for n in child.scope_types
                ]
                attr["option_types"] = [
                    v9_fieldtypes.LABEL.get(n, n) for n in child.option_types
                ]
                attr["option_lengths"] = child.option_lengths

        return templates


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
