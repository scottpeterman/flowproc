
"""
The stateful parts of NetFlow V9 parsing - i.e. templates and
exporter attributes and options.
"""

import logging

# global settings
logger = logging.getLogger(__name__)


class Template:
    """
    Responsibility: represent Template Record
    """

    # dict for all the collector's templates
    tdict = {}

    def __init__(self, tid, tdata):
        self.tid = tid
        self.tdata = tdata
        try:
            template = Template.tdict[tid]
            if self.__repr__() == template.__repr__():
                logger.info("Renewing template {:d}".format(tid))
            else:
                logger.warning("Replacing template {:d}".format(tid))
        except KeyError:
            logger.info("Creating template {:d}".format(tid))
        finally:
            Template.tdict[tid] = self

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

    def __repr__(self):
        return self.tid, self.tdata


class OptionsTemplate(Template):
    """
    Responsibility: represent Options Template Record attributes
    """

    def __init__(self, tid, tdata, scopelen, optionlen):
        self.tid = tid
        self.tdata = tdata
        self.scopelen = scopelen
        self.optionlen = optionlen
        try:
            template = Template.tdict[tid]
            if self.__repr__() == template.__repr__():
                logger.info("Renewing options template {:d}".format(tid))
            else:
                logger.warning("Replacing options template {:d}".format(tid))
        except KeyError:
            logger.info("Creating options template {:d}".format(tid))
        finally:
            Template.tdict[tid] = self

    def __repr__(self):
        return self.tid, self.tdata, self.scopelen, self.optionlen
