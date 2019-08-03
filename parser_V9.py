import logging
import struct
import sys

# global settings
logger = logging.getLogger(__name__)
fmt1 = logging.Formatter("[%(asctime)s] %(levelname)-8s %(name)s: %(message)s")
fmt2 = logging.Formatter("%(levelname)-8s %(message)s")
sh = logging.StreamHandler(sys.stderr)
sh.setFormatter(fmt2)
logger.setLevel(logging.DEBUG)
logger.addHandler(sh)

LIM = 1800  # Out of sequence tdiff limit for discarding templates
lim = LIM


def handle_unspecified(setid, packed):
    """
    Responsibility: handle what is not known
    """
    logger.error(
        "No implementation for unknown ID {:3d} - {}".format(setid, packed)
    )


def parse_data_flowset(tid, packed):
    """
    Responsibility: parse Data FlowSets

    Args:
        tid         `int`: the setid here IS the tid (aka Template ID)
        packed      `bytes`: data to parse

    Return:
        number of records processed
    """
    record_count = 0

    try:
        template = Template.get(tid)

        # TODO Implement instead of doing this placeholder stuff:
        logger.debug("{} {}".format(tid, template.types))
        reclen = sum(template.lengths)

        record_count = len(packed) // reclen  # // division to rule out padding

    except KeyError:
        logger.warning(
            "No template, discarding Data FlowSet ID {:d}".format(tid)
        )

    return record_count


class OptionsTemplate:
    """
    Responsibility: represent Options Template Record
    """
    # TODO Use or delete!


def parse_options_template_flowset(packed):
    """
    Responsibility: parse Options Template FlowSet

    Args:
        packed      `bytes`: data to parse

    Return:
        number of records processed
    """
    record_count = 0

    start = 0
    stop = 6
    assert len(packed[start:stop]) == stop

    # TODO Replace this by a proper implementation.
    unpacked = struct.unpack("!HHH", packed[start:stop])
    Template(unpacked[0], unpacked[1:])

    return 1


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


def parse_template_flowset(packed):
    """
    Responsibility: parse Template FlowSet

    Args:
        packed      `bytes`: data to parse

    Return:
        number of records processed
    """
    record_count = 0

    start = 0
    while True:
        stop = start + 4
        try:
            assert len(packed[start:stop]) == 4
        except AssertionError:
            break  # FlowSet done

        # next Template ID and Field Count
        tid, fieldcount = struct.unpack("!HH", packed[start:stop])
        start = stop

        # record data
        tdata = []
        while fieldcount > 0:
            stop = start + 4
            tdata += struct.unpack("!HH", packed[start:stop])
            start = stop
            fieldcount -= 1

        Template(tid, tdata)
        record_count += 1

    return record_count


def dispatch_flowset(setid, packed):
    """
    Responsibility: dispatch FlowSet data to the appropriate parser

    Args:
        setid       `int`: the setid here IS the tid (aka Template ID)
        packed      `bytes`: data to dispatch

    Return:
        number of records processed
    """
    record_count = 0

    if setid == 0:
        # Template FlowSet
        record_count += parse_template_flowset(packed)
    elif setid == 1:
        # Options Template FlowSet
        record_count += parse_options_template_flowset(packed)
    elif 255 < setid and setid < 65536:
        # Data FlowSet
        record_count += parse_data_flowset(setid, packed)
    else:
        # [2, 255]
        handle_unspecified(setid, packed)

    return record_count


def parse_file(fh):
    """
    Responsibility: parse raw NetFlow V9 data from disk.
    """
    lastseq = None
    lastup = None
    count = None
    record_count = 0

    while True:
        pos = fh.tell()
        packed = fh.read(4)

        try:
            assert len(packed) == 4
        except AssertionError:
            # EOF
            return

        # Unpack, expecting the next FlowSet.
        setid, setlen = struct.unpack("!HH", packed)

        if setid != 9:
            packed = fh.read(setlen - 4)
            assert len(packed) == setlen - 4
            record_count += dispatch_flowset(setid, packed)

        else:
            # for completeness' sake
            if count:
                if count != record_count:
                    logger.warning(
                        "Record account not balanced {}/{}".format(
                            count, record_count
                        )
                    )

            # next packet header
            fh.seek(pos)
            packed = fh.read(20)
            assert len(packed) == 20
            header = struct.unpack("!HHIIII", packed)

            logger.debug(header)

            # sequence checks
            up = header[2]
            seq = header[4]
            if lastup and lastseq:
                if seq != lastseq + 1:
                    updiff = up - lastup
                    logger.warning(
                        "Out of seq, lost {}, tdiff {:.1f} s".format(
                            seq - lastseq, round(updiff / 1000, 1)
                        )
                    )
                    if updiff > lim * 1000:
                        logger.warning("Discarding templates")
                        Template.discard_all()

            lastup = up
            lastseq = seq
            count = header[1]
            record_count = 0


with open(sys.argv[1], "rb") as fh:

    parse_file(fh)
