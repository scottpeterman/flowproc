# -*- coding: utf-8 -*-
"""
Basic packet test V9
"""

__author__ = "Tobias Frei"
__copyright__ = "Tobias Frei"
__license__ = "mit"

import io
import logging

# import pytest

from flowproc import v9_parser

logging.getLogger().setLevel(logging.DEBUG)

# The flowset with 2 templates and 8 flows
template_packet = "0009000a000000035c9f55980000000100000000000000400400000e00080004000c000400150004001600040001000400020004000a0004000e000400070002000b00020004000100060001003c000100050001000000400800000e001b0010001c001000150004001600040001000400020004000a0004000e000400070002000b00020004000100060001003c000100050001040001447f0000017f000001fb3c1aaafb3c18fd000190100000004b00000000000000000050942c061b04007f0000017f000001fb3c1aaafb3c18fd00000f94000000360000000000000000942c0050061f04007f0000017f000001fb3c1cfcfb3c1a9b0000d3fc0000002a000000000000000000509434061b04007f0000017f000001fb3c1cfcfb3c1a9b00000a490000001e000000000000000094340050061f04007f0000017f000001fb3bb82cfb3ba48b000002960000000300000000000000000050942a061904007f0000017f000001fb3bb82cfb3ba48b00000068000000020000000000000000942a0050061104007f0000017f000001fb3c1900fb3c18fe0000004c0000000100000000000000000035b3c9110004007f0000017f000001fb3c1900fb3c18fe0000003c000000010000000000000000b3c9003511000400"

# Three packets without templates, each with 12 flows, anonymized
packets = [
    "0009000c000000035c9f55980000000200000000040001e47f0000017f000001fb3c1a17fb3c19fd000001480000000200000000000000000035ea82110004007f0000017f000001fb3c1a17fb3c19fd0000007a000000020000000000000000ea820035110004007f0000017f000001fb3c1a17fb3c19fd000000f80000000200000000000000000035c6e2110004007f0000017f000001fb3c1a17fb3c19fd0000007a000000020000000000000000c6e20035110004007f0000017f000001fb3c1a9efb3c1a9c0000004c0000000100000000000000000035adc1110004007f0000017f000001fb3c1a9efb3c1a9c0000003c000000010000000000000000adc10035110004007f0000017f000001fb3c1b74fb3c1b720000004c0000000100000000000000000035d0b3110004007f0000017f000001fb3c1b74fb3c1b720000003c000000010000000000000000d0b30035110004007f0000017f000001fb3c2f59fb3c1b7100001a350000000a000000000000000000509436061b04007f0000017f000001fb3c2f59fb3c1b710000038a0000000a000000000000000094360050061b04007f0000017f000001fb3c913bfb3c91380000004c0000000100000000000000000035e262110004007f0000017f000001fb3c913bfb3c91380000003c000000010000000000000000e262003511000400",
    "0009000c000000035c9f55980000000300000000040001e47f0000017f000001fb3ca523fb3c913b0000030700000005000000000000000000509438061b04007f0000017f000001fb3ca523fb3c913b000002a200000005000000000000000094380050061b04007f0000017f000001fb3f7fe1fb3dbc970002d52800000097000000000000000001bb8730061b04007f0000017f000001fb3f7fe1fb3dbc970000146c000000520000000000000000873001bb061f04007f0000017f000001fb3d066ffb3d066c0000004c0000000100000000000000000035e5bd110004007f0000017f000001fb3d066ffb3d066c0000003c000000010000000000000000e5bd0035110004007f0000017f000001fb3d1a61fb3d066b000003060000000500000000000000000050943a061b04007f0000017f000001fb3d1a61fb3d066b000002a2000000050000000000000000943a0050061b04007f0000017f000001fb3fed00fb3f002c0000344000000016000000000000000001bbae50061f04007f0000017f000001fb3fed00fb3f002c00000a47000000120000000000000000ae5001bb061b04007f0000017f000001fb402f17fb402a750003524c000000a5000000000000000001bbc48c061b04007f0000017f000001fb402f17fb402a75000020a60000007e0000000000000000c48c01bb061f0400",
    "0009000c000000035c9f55980000000400000000040001e47f0000017f000001fb3d7ba2fb3d7ba00000004c0000000100000000000000000035a399110004007f0000017f000001fb3d7ba2fb3d7ba00000003c000000010000000000000000a3990035110004007f0000017f000001fb3d8f85fb3d7b9f000003070000000500000000000000000050943c061b04007f0000017f000001fb3d8f85fb3d7b9f000002a2000000050000000000000000943c0050061b04007f0000017f000001fb3d9165fb3d7f6d0000c97b0000002a000000000000000001bbae48061b04007f0000017f000001fb3d9165fb3d7f6d000007f40000001a0000000000000000ae4801bb061b04007f0000017f000001fb3dbc96fb3dbc7e0000011e0000000200000000000000000035bd4f110004007f0000017f000001fb3dbc96fb3dbc7e0000008e000000020000000000000000bd4f0035110004007f0000017f000001fb3ddbb3fb3c1a180000bfee0000002f00000000000000000050ae56061b04007f0000017f000001fb3ddbb3fb3c1a1800000982000000270000000000000000ae560050061b04007f0000017f000001fb3ddbb3fb3c1a180000130e0000001200000000000000000050e820061b04007f0000017f000001fb3ddbb3fb3c1a180000059c000000140000000000000000e8200050061b0400",
]


def test_v9_parse_Template():
    fh = io.BytesIO(bytes.fromhex(template_packet))
    v9_parser.parse_file(fh)


def test_v9_parse_Packets():
    for p in packets:
        v9_parser.parse_file(io.BytesIO(bytes.fromhex(p)))
