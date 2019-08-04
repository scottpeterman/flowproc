flowproc
========

Python network flow processing collector and library

.. image:: https://img.shields.io/pypi/v/flowproc.svg
        :target: https://pypi.python.org/pypi/flowproc/
        :alt: Latest Version

.. image:: https://travis-ci.com/shuntingyard/flowproc.svg?branch=master
        :target: https://travis-ci.com/shuntingyard/flowproc
        :alt: Travis

.. image:: https://img.shields.io/pypi/l/flowproc.svg
        :target: http://github.com/shuntingyard/flowproc/blob/master/LICENSE.txt
        :alt: License

.. image:: https://img.shields.io/pypi/pyversions/flowproc.svg
        :target: https://pypi.python.org/pypi/flowproc/
        :alt: Versions

Description
-----------

Parser for NetFlow V5 ready, V9 under way and progressing fast, IPFIX next
target.

Dependency on operating systems: to clarify.

Recent changes
--------------

- Added support for textual representation of IANA-assigned port and protocol
  numbers
- Added support to get ICMP type and code from destination port number
  (Netflow V5)
- README is now PyPi-friendly

Installation
------------

Changelog
---------

Version 0.0.2
~~~~~~~~~~~~~

- Added support for textual representation of IANA-assigned port and protocol
  numbers
- Added support to get ICMP type and code from destination port number
  (Netflow V5)
- README is now PyPi-friendly
- Early development

Version 0.0.1
~~~~~~~~~~~~~

- Early development

Note
----

This project has been set up using PyScaffold 3.1. For details and usage
information on PyScaffold see https://pyscaffold.org/.
