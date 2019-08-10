# TODO list

- [ ] Tidy up template classes (including abstract).

- [ ] Reimplement seq and template checks

- [ ] Get done with remaining buffering/ counting issues.

- [ ] Log all events demanded/ recommended in RFC 3954.

- [ ] Improve some log messages with ID for exporter (ipa + odid).

- [ ] Faster parsing, identify spots to replace 'struct.unpack'
  by the 'Struct' class.

- [ ] Faster collector state implementation (cython or numba with
  numpy arrays)?

- [x] Assure this runs on all targeted 3.x versions (asyncio, drop 3.4, 3.5?).

- [ ] Switch to gpl2 license for at least core things?

- [ ] Terminology cleanup in doc and docstrings.

- [ ] Integrate v5_parser properly.

- [ ] Implement the INFIX parsing/ state handling part!

- [ ] Write and performance-eval the fluent part.

- [ ] Implement a cmdl example for fluent/workflow (a bit like tcpdump)

- [ ] Implement a dash/ plotly (or maybe just old rrdtool) example for
  SOHO or your-network-at-a-glance use.

- [ ] Release 0.1.0
