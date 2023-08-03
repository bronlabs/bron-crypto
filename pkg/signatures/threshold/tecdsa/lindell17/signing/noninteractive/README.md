# Lindell 2017 Non-interactive signing
This is essentially [interactive signing](../interactive/README.md) from [Fast Secure Two-Party ECDSA Signing][Lin17] split into PreGen and Sign phase.
The PreGen consist of Round 1-3, where at last round each party stores $c_3$ as the pre-signature
and the Non-Interactive Sign consist of Round 4 which requires the message $c_3$ and the message to produce final ECDSA signature.
