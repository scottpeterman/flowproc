"""
The stateful parts of NetFlow V9 parsing - i.e. templates and
exporter attributes and options.
"""

import logging

from datetime import datetime

from flowproc.collector_state import AbstractTemplate
from flowproc.collector_state import Collector

# global settings
logger = logging.getLogger(__name__)


class Template(AbstractTemplate):
    """
    Responsibility: represent Template Record
    """

    # dict for all the collector's templates
    tdict = {}

    def __init__(self, ipa, odid, tid, tdata):
        self.tid = tid
        self.tdata = tdata
        self.lastwrite = datetime.utcnow()  # TODO add timezone info

        Collector.register(ipa, odid, self)

    @classmethod
    def get(cls, tid):
        """
        Return:
            `Template` or raise `KeyError`
        """
        return cls.tdict[tid]

    @classmethod
    def discard_all(cls):
        """
        Discard all templates
        """
        cls.tdict = {}

    @property
    def types(self):
        return self.tdata[0::2]  # using start::step for all field types

    @property
    def lengths(self):
        return self.tdata[1::2]  # same for all field lengths

    def __str__(self):
        return "{:d} age={} types={}".format(
            self.tid, datetime.utcnow() - self.lastwrite, self.types
        )

    def __repr__(self):
        return self.tid, self.tdata

    def get_tid(self):
        return self.tid


class OptionsTemplate(Template):
    """
    Responsibility: represent Options Template Record attributes
    """

    def __init__(self, ipa, odid, tid, tdata, scopelen, optionlen):
        self.tid = tid
        self.tdata = tdata
        self.lastwrite = datetime.utcnow()  # TODO add timezone info
        self.scopelen = scopelen
        self.optionlen = optionlen

        Collector.register(ipa, odid, self)

    def __repr__(self):
        return self.tid, self.tdata, self.scopelen, self.optionlen
