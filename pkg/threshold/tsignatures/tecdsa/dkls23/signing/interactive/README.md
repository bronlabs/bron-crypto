# DKLs23 Interactive Signing

This package implements the 3-round, (t, n) signing protocol of [DKLs23](https://eprint.iacr.org/2023/765.pdf), realizing the standard ECDSA functionality defined as Functionality 3.1 in the paper.

The details of the protocol are sketched in Protocol 3.6 of the main paper. We are largely faithful to the original paper except:
1. We have confirmation from the DKLs team that the 2nd consistency check of the paper has a typo, which we fix.
2. We'll compute the recovery id and extend the ECDSA signature with it.
3. $R_i$ is included in the partial signature, for the aggregator to compute the sum itself, as well as be able to compute the recovery id independently.


## Configuration

**Players**:
- `n` players where at least `t` of them are present during the signing session.
- At least one signature aggregator, who may or may not be a player.

**Parameters**:
- Follows whatever is defined in the subprotocols used.

**Functionalities**:
- `RVOLE` The two party multiplication protocol.
- `Zero` The zero share sampling protocol (PRZS).
- `Commit` Commitment functionality which can commit and open
- `H(x,L)` Hash function, input x of variable size, output of size $\mathbb{Z}_q^L$. For ECDSA, this is typically SHA2.
- `Send(x)=> P` Send message x to party P.
- `Broadcast(x)` Echo-broadcasts x to all parties.

**Input**:
- UniqueSessionId
- Message $m$ (given in the 3rd round)

**Output**:
- Partial Signature (end of round 3)
- Signature (end of aggregation - which may happen immediately after round 3)

## Protocol:

This protocol is symmetric: In every round, all parties do the same thing.

0. Init:
    1. DKG
    2. Zero share sampling seed.
    3. Compute COTe.Setup (init S&R in SoftspokenOT with [ $\kappa \times$ BaseOT] seeds) and construct pairwise multiplication instances.

1. Round 1:
    1. Compute inversion mask $phi_i \leftarrow \mathbb{Z}_q$
    2. Compute instance key $r_i \leftarrow \mathbb{Z}_q$
    3. Compute $R_i = r_i \cdot G$
    3. For all present parties p_j:
        1. $c, w = Commit(p_i, p_j, sid, R_i)$ where `c` is the commitment and `w` the witness. Store `w`.
        2. Run first round of `RVOLE` as bob and record the output as `multiplicationOutput`.
        3. Record Bob's input (with forced-resuse it'll be $\tilde{b}$) as $\chi_{ij}$
        4. `Send(c, multiplicationOutput) => P_j`
    4. `Broadcast(R_i)`

2. Round 2:
    1. Receive $\zeta_i$ from the zero share sampling subprotocol.
    2. Convert shamir share of the private key to additive to get `a`.
    3. Compute $sk_i=a+\zeta_i$
    4. Compute $pk_i=sk_i \cdot G$
    5. Set multiplication input $a = \{r_i, sk_i\}
    6. For all present parties p_j:
        1. Receive broadcasted `R_ij`
        2. Receive unicasted `commitment_j` and `multiplicationOutput_j`
        3. Run 2nd round of `RVOLE` as Alice and record the output as $c^u_{ij}$ and $c^v_{ij}$ as well as `multiplicationOutput`.
        4. Set $\Gamma^u_{ij} = c^u_{ij} \cdot G$
        5. Set $\Gamma^v_{ij} = c^v_{ij} \cdot G$
        6. Set $\psi_{ij} = \phi_i - \chi_{ij}$
        7. Send the `multiplicationOutput`, $\Gamma^u_{ij}$, $\gamma^v_{ij}$, $\psi_{ij}$ and opening of the commitment `c` corresponding to p_j.
    7. Broadcast $pk_i$.

3. Round 3 (ABORTs here, like all our protocols, are global and should affect all running sessions):
    1. For all present parties p_j:
        1. Receive $pk_j$.
        2. Receive $\Gamma^u_{ji}$ and $\gamma^v_{ji}$, `multiplicationOutput` and the witness.
        3. **ABORT** if $(p_j, p_i, sid, R_j)$ can't be opened.
        4. Run the 3rd round of `RVOLE` as bob with the received `multiplicationOutput` to get $d^u_{ij}$ and $d^v_{ij}$.
        5. **ABORT** if $\chi_{ij} \cdot R_j - \Gamma^u_{ji} \neq d^u_{ij} \cdot G$
        6. **ABORT** if $\chi_{ij} \cdot pk_i - \Gamma^v_{ji} \neq d^v_{ij} \cdot G$
    2. **ABORT** if sum of all $pk_j$ as well as $pk_i$ is not equal to the public key.
    3. Compute $R = \sum R_j$
    4. Compute $u_j = r_i \cdot (\phi_i + \sum psi_{ji}) + \sum (c^u_{ij} + d^u_{ij})$
    5. Compute $v_j = sk_i \cdot (\phi_i + \sum psi_{ji}) + \sum (c^v_{ij} + d^v_{ij})$
    6. Compute $w_i = SHA2(m) \cdot \phi_i + (R.x) \cdot v_i$ where $(R.x)$ is the x-coordinate of $.
    7. Broadcasts $u_i$ and $w_i$.

4. Aggregation
   1. Receive $u_i$, $w_i$ and $R_i$.
   2. Set $r$ to be x coodinate of $\sum R_i$
   3. Set $s = \cfrac{\sum w_i}{\sum u_i}$
   4. Comput recovery id `v`
   5. Set $\sigma=(v, r, s)$.
   6. Normalize the signature (convert to low-s form and adjust `v`)
   7. **ABORT** if $\sigma$ can't be verified.
   8. Output $\sigma$




## Best-effort Constant Time implementation

The code of this package is written in a best-effort mode to be Constant Time by: 
1. Removing data-dependent branching (e.g. if-else statements) and data-dependent iteration (e.g. data-dependent length of for-loops)
2. Using constant-time operations from primitives (e.g. constant-time field operations from `saferith`)
3. Delaying error/abort raising when tied to data (e.g., for loops in consistency checks) to avoid leaking unnecessary stop information. Note that this does not cover "static" errors (e.g., wrong size for hashing).
4. Using `crypto/subtle` functions whenever applicable.