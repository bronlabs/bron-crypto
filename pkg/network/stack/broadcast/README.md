# Broadcast
Defined a layer which decorates authenticated (signed and/or encrypted) peer-to-peer exchanges to provide reliable[^1]
broadcast functionality atop of it.
The PoC version uses simple echo broadcast algorithm.
The implementation would be greatly simplified if instead of using channels Mutex and Condition Variable is used.

[^1]: reliable means if the broadcaster is non-faulty then all non-faulty parties will output the broadcaster’s input
and if some non-faulty party outputs a value then all non-faulty parties will output the same value.
