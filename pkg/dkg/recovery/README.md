# Share Recovery

This package implements a protocol that allows share recovery without reconstructing the private key: In a (t, n) threshold configuration, `t` parties will need to perform some computation so that the aggregate of them is the lost share.

Note that the recovered share, is exactly equal to the lost share. It is therefore recommended that the user performs a key refresh immediately after to invalidate the lost share.


## Configuration

**Players**:
- `n` players where at least `t+1` of them are present during the recovery session, and only one has lost her share.

**Functionalities**:
- `Sample` Sample a zero share (HJKY)
- `L_i(x_0)` computes i'th lagrange basis polynomial evaluated at `x_0`
- `Send(x)=> P` Send message x to party P.
- `Broadcast(x)` Echo-broadcasts x to all parties.

**Input**:
- UniqueSessionId
- Public Key Shares
- Signing Key Share (if recoverer)

**Output**:
- To the party who lost her share: The share.
- To the recoverers: Nothing.

## Protocol

In the first round all parties do the same thing. In the second round, the party with a lost share doesn't send any messages. In the third round, the recoverers don't do anything.

0. Init.
   1. DKG

1. Round 1.
   1. Do Round1 of `Sample`.

2. Round 2.
   0. Receive Round1 Outputs
   1. Derive `sample` by computing Roun 2 of `Sample`
   2. Convert `sample` to additive and store in memory.
   3. If I'm recoverer:
      1. Set $lx$ = evaluate L_i at sharing id of the party with lost shares, inputting the sharing ids of all present recoverers
      2. Compute partially recovered share: $s = lx \times y$ where $y$ is my signing key share.
      3. Blind the partially recovered share $\hat{s} = s + a$ where $a$ is the additive form of the sampled zero share.
      4. Send $\hat{s}$ to the party who lost her share.

3. Round 3.
   0. Receive all outputs of Round 2.
   1. Compute $res = a + \sum \hat{s}$ where $a$ is the additive form the sampled zero share in the previous round.
   2. **ABORT** if $res \cdot G$ is not equal to the corresponding public key share.
   3. **OUTPUT** $res$
