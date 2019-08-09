"""
Template classes for NetFlow V9 parsing
"""

import logging

from datetime import datetime

from flowproc import v9_fieldtypes
from flowproc.collector_state import AbstractTemplate
from flowproc.collector_state import Collector

# global settings
logger = logging.getLogger(__name__)


class Template(AbstractTemplate):
    """
    Responsibility: represent Template Record
    """

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
            self.tid,
            datetime.utcnow() - self.lastwrite,
            [v9_fieldtypes.LABEL.get(n, n) for n in self.types],
        )

    def __repr__(self):
        return self.tid, self.tdata  # TODO Should be string!

    def get_tid(self):
        return self.tid


class OptionsTemplate(AbstractTemplate):
    """
    Responsibility: represent Options Template Record attributes
    """

    def __init__(self, ipa, odid, tid, scopes, options):
        self.tid = tid
        self.scopes = scopes
        self.options = options
        self.lastwrite = datetime.utcnow()  # TODO add timezone info

        Collector.register(ipa, odid, self)

    @classmethod
    def get(cls, tid):
        """
        Return:
            `Template` or raise `KeyError`
        """
        return cls.tdict[tid]

    @property
    def scope_types(self):
        return self.scopes[0::2]  # using start::step for all field types

    @property
    def scope_lengths(self):
        return self.scopes[1::2]  # same for all field lengths

    @property
    def option_types(self):
        return self.options[0::2]  # as above

    @property
    def option_lengths(self):
        return self.options[1::2]  # as above

    def __str__(self):
        return "{:d} age={} scopes={} options={}".format(
            self.tid,
            datetime.utcnow() - self.lastwrite,
            [
                v9_fieldtypes.SCOPE_LABEL.get(n, n)
                for n in self.scope_types
            ],
            [
                v9_fieldtypes.LABEL.get(n, n)
                for n in self.option_types
            ],
        )

    def __repr__(self):
        return self.tid, self.scopes, self.options  # TODO Should be string!

    def get_tid(self):
        return self.tid
