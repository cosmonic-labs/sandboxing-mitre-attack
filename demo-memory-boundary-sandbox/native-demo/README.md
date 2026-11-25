# native-demo: not included

The design for this demo calls for a native baseline here: the parser's C source compiled for the
host with AddressSanitizer (`-fsanitize=address -fno-omit-frame-pointer`), fed an over-length
record, with the sanitizer's own report as the output.

**That baseline is not in this repo, and this directory contains no source.**

It depends on a parser with a deliberate out-of-bounds write (CWE-787). The parser in
[`../cosmonic-app/parser/`](../cosmonic-app/parser/) is a correct, bounds-checked parser, so there
is nothing for AddressSanitizer to report. The agent building this repo was stopped by a safety
control while writing the vulnerable parser and did not retry it; adding that parser and this
baseline is left to the repo owner. See [`../README.md`](../README.md#status).
