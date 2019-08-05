# -*- coding: utf-8 -*-
"""
Parser for NetFlow V9 packets
"""

import logging
import struct

# from flowproc import util
from flowproc import v9_state

__author__ = "Tobias Frei"
__copyright__ = "Tobias Frei"
__license__ = "mit"

# global settings
logger = logging.getLogger(__name__)
LIM = 1800  # out of sequence tdiff limit for discarding templates
lim = LIM


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
        template = v9_state.Template.get(tid)

        if isinstance(template, v9_state.OptionsTemplate):
            logger.debug("OT {} {} {}".format(template.scopelen, template.optionlen, template.types))
        else:
            logger.debug("T  {} {}".format(tid, template.types))

        reclen = sum(template.lengths)
        record_count = len(packed) // reclen  # divide // to rule out padding

    except KeyError:
        logger.debug(
            "No template, discarding Data FlowSet ID {:d}".format(tid)
        )

    return record_count


def parse_options_template_flowset(packed):
    """
    Responsibility: parse Options Template FlowSet

    Args:
        packed      `bytes`: data to parse

    Return:
        number of records processed
    """
    record_count = 1

    start = 0
    stop = 6

    unpacked = struct.unpack("!HHH", packed[start:stop])
    tid, scopelen, optionlen = unpacked

    start = stop
    reclen = scopelen + optionlen
    stop += reclen

    tbytes = packed[start:stop]
    assert reclen % 4 == 0
    tdata = struct.unpack("!" + "HH" * (reclen // 4), tbytes)

    v9_state.OptionsTemplate(tid, tdata, scopelen, optionlen)

    return record_count


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
        stop += (fieldcount * 4)

        tbytes = packed[start:stop]
        tdata = struct.unpack("!" + "HH" * fieldcount, tbytes)

        start = stop

        v9_state.Template(tid, tdata)
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
        # interval [2, 255]
        logger.error(
            "No implementation for unknown ID {:3d} - {}".format(
                setid, packed
            )
        )

    return record_count


def parse_packet(datagram, ipa):
    """
    Responsibility: parse UDP packet received from NetFlow V9 exporter

    Args:
        packet  `bytes`: next packet to parse
        ipa     `str` or `int`: ip address to use for identification in
                                `flowproc.util.Exporter`
    """
    logger.warning("Alpha, parsing packet {} WITHOUT checks!".format(
            struct.unpack("!HHIIII", datagram[:20])
        )
    )

    packed = datagram[20:]

    while len(packed) > 0:

        # FlowSet header
        setid, setlen = struct.unpack("!HH", packed[:4])

        # data
        data = packed[4:setlen]
        dispatch_flowset(setid, data)

        packed = packed[setlen:]


def parse_file(fh, ipa):
    """
    Responsibility: parse raw NetFlow V9 data from disk.

    Args:
        fh      `BufferedReader`, BytesIO` etc: input file handle
        ipa     `str` or `int`: ip addr to use for `Exporter` identification
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
                else:
                    logger.debug("Processed {} records".format(count))

            # next packet header
            fh.seek(pos)
            packed = fh.read(20)
            assert len(packed) == 20
            header = struct.unpack("!HHIIII", packed)

            logger.info(header)

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
                        v9_state.Template.discard_all()

            lastup = up
            lastseq = seq
            count = header[1]
            record_count = 0
