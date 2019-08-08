# -*- coding: utf-8 -*-
"""
Experiment on dealing with state
"""

import logging

from abc import ABC
from abc import abstractmethod
from datetime import datetime
from ipaddress import ip_address

__author__ = "Tobias Frei"
__copyright__ = "Tobias Frei"
__license__ = "mit"

# globals
logger = logging.getLogger(__name__)


class AbstractTemplate(ABC):
    """
    The things every temlate class should implement
    """

    @abstractmethod
    def get_tid(self):
        pass


class Visitable(ABC):
    """
    Use a generic way to make classes visitable (thanks Wikipedia)
    """

    def accept(self, visitor):
        lookup = "visit_" + type(self).__qualname__.replace(".", "_")
        return getattr(visitor, lookup)(self)


class Collector:
    """
    Not to instantiate - contains exclusively class- and static methods.
    """

    children = {}
    created = datetime.now()
    packets = 0
    count = 0
    record_count = 0

    @classmethod
    def accept(cls, visitor):
        lookup = "visit_" + cls.__qualname__.replace(".", "_")
        return getattr(visitor, lookup)(cls)

    @classmethod
    def check_header(cls, ipa, packet):
        """
        Run sequence checks, restart checks etc. and manage templates
        behind the scenes.
        """
        pass

    @classmethod
    def get_qualified(cls, *args):
        """
        Get an object under this collector
        """
        # A simple idiom to fill a fixed len list from (variable len) *args:
        path = [args[i] if i < len(args) else None for i in range(3)]
        return cls.accept(RetrievingVisitor(*path))

    @classmethod
    def register(cls, ipa, odid, template):
        """
        Create, update or replace anything implementing `AbstractTemplate`
        """
        cls.accept(RegisteringVisitor(ipa, odid, template))

    @classmethod
    def unregister(cls, ipa, odid):
        """
        Remove rightmost element in path (and its child nodes)
        """


class Exporter(Visitable):
    """
    TODO Clarify relation to observation domains (and for V10) transport
         protocols.
    """

    def __init__(self, ipa):
        self.children = {}
        self.ipa = ip_address(ipa).exploded

    def __repr__(self):
        return self.ipa


class ObservationDomain(Visitable):
    """
    TODO Clarify relation to exporters (and for V10) transport protocols.
    """

    def __init__(self, odid):
        self.children = {}
        self.odid = int(odid)
        self.optrecs = []  # option data records collected for self

    def __repr__(self):
        return str(self.odid)


class RetrievingVisitor:
    """
    Return the object on the path defined by ID values received  as
    '__init__' args if it exists, else return 'None'.

    Args:
        ipa         `str`, `int`: ip address of exporter
        odid        `int`: Observation Domain ID
        tid         `int`: Template ID

    TODO Document collector's class methods with similar text (and maybe don't
         even document visitors this extensively, since they're implementation
         internal).
    """

    def __init__(self, ipa, odid, tid):
        self.ipa = ipa
        self.odid = odid
        self.tid = tid

    def visit_Collector(self, host):
        if self.ipa is not None:  # if next element in path
            try:
                return host.children[self.ipa].accept(self)
            except KeyError:
                return None
        return host

    def visit_Exporter(self, host):
        if self.odid is not None:  # if next element in path
            try:
                return host.children[self.odid].accept(self)
            except KeyError:
                return None
        return host

    def visit_ObservationDomain(self, host):
        if self.tid is not None:  # if next element in path
            try:
                # Template level, just get - don't visit!
                return host.children[self.tid]
            except KeyError:
                return None
        return host


class RegisteringVisitor:
    """
    Store the template object received as '__init__' arg and create other
    objects on the path (Collector -> Exporter -> ObservationDomain) to it.

    TODO See above, other visitor...
    """

    def __init__(self, ipa, odid, template_obj):
        self.ipa = ipa
        self.odid = odid
        self.template = template_obj

    def visit_Collector(self, host):
        exporter = host.children.get(self.ipa, Exporter(self.ipa))
        host.children[self.ipa] = exporter
        exporter.accept(self)

    def visit_Exporter(self, host):
        domain = host.children.get(self.odid, ObservationDomain(self.odid))
        host.children[self.odid] = domain
        domain.accept(self)

    def visit_ObservationDomain(self, host):
        tid = self.template.get_tid()
        try:
            val = host.children[self.template.get_tid()]
            # hope this helps us work around the timestamp of refreshment
            if val.__repr__() == self.template.__repr__():
                logger.debug(
                    "Updating {} with tid {:d}".format(
                        type(self.template), tid
                    )
                )
            else:
                logger.warning(
                    "Replacing {} with tid {:d}".format(
                        type(self.template), tid
                    )
                )
        except KeyError:
            logger.info(
                "Creating {} with tid {:d}".format(type(self.template), tid)
            )
        # at last DO it
        host.children[tid] = self.template


class TraversingVisitor:
    """
    The precursor to stats, should it have a return value or just do something
    (like printing)?
    """

    def visit_Collector(self, host):
        for child in host.children.values():
            print(child)
            child.accept(self)

    def visit_Exporter(self, host):
        for child in host.children.values():
            print(child)
            child.accept(self)

    def visit_ObservationDomain(self, host):
        for child in host.children.values():
            print(child)


class _TraversingDictVisitor:
    """
    Mainly written for debugging
    """

    def visit_Collector(self, host):
        [print(k, type(k), v, type(v)) for k, v in host.children.items()]
        for child in host.children.values():
            child.accept(self)

    def visit_Exporter(self, host):
        [print(k, type(k), v, type(v)) for k, v in host.children.items()]
        for child in host.children.values():
            child.accept(self)

    def visit_ObservationDomain(self, host):
        [print(k, type(k), v, type(v)) for k, v in host.children.items()]
