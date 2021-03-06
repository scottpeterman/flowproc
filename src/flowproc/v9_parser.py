# -*- coding: utf-8 -*-
"""
Parser for NetFlow V9 packets
"""

import logging
import struct

from ipaddress import ip_address

from flowproc import util
from flowproc import v9_fieldtypes
from flowproc.collector_state import Collector
from flowproc.v9_classes import OptionsTemplate
from flowproc.v9_classes import Template

__author__ = "Tobias Frei"
__copyright__ = "Tobias Frei"
__license__ = "mit"

# global settings
logger = logging.getLogger(__name__)
LIM = 1800  # out of sequence tdiff limit for discarding templates
lim = LIM


@util.stopwatch
def parse_options_data_records(ipa, odid, template, flowset):
    """
    Responsibility: parse Data FlowSet with Options Data Records

    Args:
        ipa         `str`: ip address of exporter
        odid        `int`: Observation Domain ID (aka Source ID)
        template    `OptionsTemplate`
        flowset     `bytes`: the DataFlowSet

    Return:
        number of records processed
    """
    record_count = 0

    # scopes part
    scopes = {}
    unpacked = []
    start = 0
    stop = start
    for length in template.scope_lengths:
        stop += length

        unpacked.append(
            struct.unpack(util.ffs(length), flowset[start:stop])[0]
        )
        start = stop

    labels = [
        v9_fieldtypes.SCOPE_LABEL.get(n, n) for n in template.scope_types
    ]
    scopes.update(list(zip(labels, unpacked)))

    # options part
    options = {}
    unpacked = []

    # To fix a few bad field lengths, we work with lengt/type-pairs
    pair = list(zip(template.option_lengths, template.option_types))
    for length, ftype in pair:
        stop += length

        try:
            unpacked.append(
                struct.unpack(
                    util.ffs(length, ftype=ftype), flowset[start:stop]
                )[0]
            )
        except KeyError:
            # remove from 1st trailing \x00 and decode to `str`
            unpacked.append(flowset[start:stop].partition(b"\0")[0].decode())
        start = stop

    labels = [v9_fieldtypes.LABEL.get(n, n) for n in template.option_types]
    options.update(list(zip(labels, unpacked)))

    # register record with corresponding odid
    optrec = scopes.update(options)
    Collector.register_optrec(ipa, odid, optrec)

    print("OptionsDataRec: {}".format(optrec))

    reclen = sum(template.scope_lengths) + sum(template.option_lengths)
    record_count = len(flowset) // reclen  # divide // to rule out padding

    return record_count


@util.stopwatch
def parse_data_flowset(ipa, odid, tid, flowset):
    """
    Responsibility: parse Data FlowSet

    Args:
        ipa         `str`: ip address of exporter
        odid        `int`: Observation Domain ID (aka Source ID)
        tid         `int`: the setid here IS the tid (aka Template ID)
        flowset     `bytes`: the DataFlowSet

    Return:
        number of records processed
    """
    record_count = 0

    template = Collector.get_qualified(ipa, odid, tid)
    if template:

        if isinstance(template, OptionsTemplate):
            return parse_options_data_records(ipa, odid, template, flowset)

        else:
            record = {}
            unpacked = []
            start = 0
            stop = start
            for length in template.lengths:
                stop += length

                unpacked.append(util.vunpack(flowset[start:stop]))
                start = stop

            labels = [v9_fieldtypes.LABEL.get(n, n) for n in template.types]
            record.update(list(zip(labels, unpacked)))

            # replace ont the fly, just for testing/ plausibility checking
            # TODO Remove later!
            for k, v in record.items():
                if k in [
                    "IPV4_SRC_ADDR",
                    "IPV4_DST_ADDR",
                    "IPV4_NEXT_HOP",
                    "IPV6_SRC_ADDR",
                    "IPV6_DST_ADDR",
                    "IPV6_NEXT_HOP",
                ]:
                    record[k] = ip_address(v).exploded

            print("DataRec: {}".format(record))

            reclen = sum(template.lengths)

        record_count = len(flowset) // reclen  # divide // to rule out padding

    else:
        # TODO Stash all these away for later processing!
        pass

    return record_count


@util.stopwatch
def parse_options_template_flowset(ipa, odid, packed):
    """
    Responsibility: parse Options Template FlowSet

    Args:
        ipa         `str`: ip address of exporter
        odid        `int`: Observation Domain ID (aka Source ID)
        packed      `bytes`: data to parse

    Return:
        number of records processed
    """
    record_count = 0

    start = 0

    # If padding, its length is 2, if not, at least 6 bytes are required.
    while start < len(packed) - 2:
        stop = start + 6

        # next Template ID, Option Scope Length and Option Length
        tid, scopelen, optionlen = struct.unpack("!HHH", packed[start:stop])

        start = stop

        # scope data
        stop += scopelen
        assert scopelen % 4 == 0  # assert before division and cast to `int`
        scopes = struct.unpack(
            "!" + "HH" * (scopelen // 4), packed[start:stop]
        )
        start = stop

        # option data
        stop += optionlen
        assert optionlen % 4 == 0  # assert before division and cast to `int`
        options = struct.unpack(
            "!" + "HH" * (optionlen // 4), packed[start:stop]
        )
        start = stop

        OptionsTemplate(ipa, odid, tid, scopes, options)
        record_count += 1

    return record_count


@util.stopwatch
def parse_template_flowset(ipa, odid, packed):
    """
    Responsibility: parse Template FlowSet

    Args:
        ipa         `str`: ip address of exporter
        odid        `int`: Observation Domain ID (aka Source ID)
        packed      `bytes`: data to parse

    Return:
        number of records processed
    """
    record_count = 0

    start = 0
    while start < len(packed):  # simple condition: no padding at end of set
        stop = start + 4

        # next Template ID and Field Count
        tid, fieldcount = struct.unpack("!HH", packed[start:stop])
        start = stop

        # record data
        stop += fieldcount * 4
        tdata = struct.unpack("!" + "HH" * fieldcount, packed[start:stop])
        start = stop

        Template(ipa, odid, tid, tdata)
        record_count += 1

    return record_count


def dispatch_flowset(ipa, odid, setid, packed):
    """
    Responsibility: dispatch FlowSet data to the appropriate parser

    Args:
        ipa         `str`: ip address of exporter
        odid        `int`: Observation Domain ID (aka Source ID)
        setid       `int`: the setid here IS the tid (aka Template ID)
        packed      `bytes`: data to dispatch

    Return:
        number of records processed
    """
    record_count = 0

    if setid == 0:
        # Template FlowSet
        record_count = parse_template_flowset(ipa, odid, packed)
    elif setid == 1:
        # Options Template FlowSet
        record_count = parse_options_template_flowset(ipa, odid, packed)
    elif 255 < setid and setid < 65536:
        # Data FlowSet
        record_count = parse_data_flowset(ipa, odid, setid, packed)
    else:
        # interval [2, 255]
        logger.error(
            "No implementation for unknown ID {:3d} - {}".format(setid, packed)
        )

    return record_count


def parse_packet(datagram, ipa):
    """
    Responsibility: parse UDP packet received from NetFlow V9 exporter

    Args:
        packet  `bytes`: next packet to parse
        ipa     `str` or `int`: ip addr to use for exporter identification
    """
    record_count = 0

    header = struct.unpack("!HHIIII", datagram[:20])
    ver, count, up, unixsecs, seq, odid = header

    packed = datagram[20:]

    while len(packed) > 0:

        # FlowSet header
        setid, setlen = struct.unpack("!HH", packed[:4])

        # data
        data = packed[4:setlen]
        record_count += dispatch_flowset(ipa, odid, setid, data)

        packed = packed[setlen:]

    if count:
        if count != record_count:
            logger.warning(
                "Record account not balanced {}/{}".format(record_count, count)
            )

    logger.info(
        "Parsed {} WITHOUT checks, {}/{} recs processed from {}".format(
            header, record_count, count, ipa
        )
    )

    # stats
    Collector.packets += 1
    Collector.count += count
    if record_count:
        Collector.record_count += record_count


def parse_file(fh, ipa):
    """
    Responsibility: parse raw NetFlow V9 data from disk.

    Args:
        fh      `BufferedReader`, BytesIO` etc: input file handle
        ipa     `str` or `int`: ip addr to use for exporter identification
    """
    lastseq = None
    lastup = None
    count = None
    record_count = 0
    odid = None

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
            record_count += dispatch_flowset(ipa, odid, setid, packed)

        else:
            # for completeness' sake
            if count:
                if count != record_count:
                    logger.warning(
                        "Record account not balanced {}/{}".format(
                            record_count, count
                        )
                    )
                else:
                    logger.debug("Processed {} records".format(count))

            # next packet header
            fh.seek(pos)
            packed = fh.read(20)
            assert len(packed) == 20
            header = struct.unpack("!HHIIII", packed)
            ver, count, up, unixsecs, seq, odid = header

            logger.info(header)

            # stats
            Collector.packets += 1
            Collector.count += count
            if record_count:
                Collector.record_count += record_count

            # sequence checks
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
