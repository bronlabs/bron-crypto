# Key Refresh based on Pedersen DKG

This is the Key Refresh protocol, allowing participants to sample zero shares and add them to their own shares, thereby changing their secret shared value of the private key while maintaining both the same public key and the same underling private key (shamir combination of private key shares).

This protocol is compatible with the output of Gennaro DKG, and it accepts a threshold signing key share and public key share and returns refreshed ones.
