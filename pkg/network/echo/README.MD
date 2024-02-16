# Echo Broadcast protocol

This implement echo broadcast protocol in [Protocol 2] https://eprint.iacr.org/2002/040.pdf. The protocol is to ensure that a message is securely broadcasted to all parties in a network.

Note that original paper does not mention authentication message. We added that so that responder can verify the message is from the sender.

## Configuration

**Players**: 3 parties, A (Alice) who is broadcasting a message to other parties and B (Bob), C (Charlie) who are receiving the message.

**Parameters**:
- $x$: the message to be broadcasted
- $sessionId$: a unique session id
- $n$: number of parties involved, with one initiator and n-1 responders. Without loss of generality, we describe the protocol for n=3 parties

**Functionalities**:
- `S(x)` Signing function
- $Send^A(x)=> [B,C]$ is a function where A uses P2P encrypted protocol to send x to parties B and C

**Inputs**:
- $A$ with inputs $x_1$

**Outputs**:
- Alice -> $x_1$
- Bob -> $x_2$
- Charlie -> $x_3$

where $x_3 = x_2 = x_1$

## Protocol

Round 1:

- 1.1: $A$ sends $Send(x_1,s_1=S(sessionId || pk^B || x_1)) => B$ and $Send(x_1,s_2=S(sessionId || pk^C || x_1)) => B$ where $pk^B$ and $pk^C$ are public keys of $B$ and $C$ respectively
- 1.2: $B$ and $C$ do nothing

Round 2:

- 2.1: $A$ does nothing
- 2.2: $B$ and $C$ verify signature $s_1$ against $A$'s public key and the authentication message $sessionId || pk^B || x_1$ and $sessionId || pk^C || x_1$
- 2.3: If the signature is invalid, identifiable abort the protocol
- 2.4: If the signature is valid, $B$ stores $x_2 = x_1$ and $Send^B(x_2,s_1) => [A,C]$. $C$ stores $x_3 = x_1$ and $Send^C(x_3,s_2) => [A,B]$

Round 3:

- 3.1: Upon receive message, each party verifies the signature $s_1$ and $s_2$ against senders (B or C). If the signature is invalid, identifiable abort the protocol
- 3.2: $A$ receives $x_2$ from $B$ and $x_3$ from $C$ then verifies that $x_2 = x_3 = x_1$. Return $x_1$ if it is, otherwise return error
- 3.3: $B$ receives $x_3$ from $C$ and verifies that $x_3 = x_2$. $C$ receives $x_2$ from $B$ and verifies that $x_2 = x_3$. Both parties return the message if it is, otherwise return error

