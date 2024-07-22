Script to generate parameters: https://github.com/o1-labs/proof-systems/blob/master/poseidon/src/pasta/params.sage

This script generates the round constants and MDS matrices for poseidon for the pasta fields.

There are two modes of operation: legacy mode and named mode.  Legacy mode is enabled when
the name argument is set to '' and the width is either 3 or 5.  These were the parameter sets
used for the first 3-wire and 5-wire poseidon instances.  These parameters are generated with:

```
   ./params.sage rust 3 ''
   ./params.sage rust 5 ''
```

The language parameter can be either "rust" or "ocaml"

Named mode is the currently used mode for parameter generation and requires each parameter
set to be given a unique name so that completely unique parameters are created for each
definition of a cryptographic hash function.  The latest 3-wire poseidon can be generated with

```
   ./params.sage rust 3 3 --rounds 54
```

Currently used names
```
Name   | Parameters
-----------------
''     | Reserved for legacy
kimchi | rounds=55, width=3, rate=2, alpha=7
```