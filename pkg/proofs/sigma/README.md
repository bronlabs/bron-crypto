This package defines a generic interface for sigma protocol and interactive compiler for running it in round-based setup where:

* Round 1: $P$ computes commitment $a$ and sends it to $V$, stores the state $s$ locally, 
* Round 2: $V$ randomly create a challenge $e$ and sends it to $P$,
* Round 3: $P$ computes response $z$ and sends to $V$,
* $V$ performs verification.

