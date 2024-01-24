# DKLS24 Non-interactive signing

* This is essentially split interactive signing into PreGen and Sign phase.
* The PreGen consist of Round 1-2, where at last round each party stores combination of $k$ participants $c_3$ as the pre-signature
and the Non-Interactive Sign consist of Round 3 which requires the message $c_3$ and the message to produce final ECDSA signature.
