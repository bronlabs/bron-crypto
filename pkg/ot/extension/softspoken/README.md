# Softspoken OT Extension
Package `softspoken` implements of maliciously secure 1-out-of-2 Correlated Oblivious Transfer extension (COTe) protocol.

We follow the designs from:
- [SoftSpokenOT](https://eprint.iacr.org/2022/192) for the OT extension
- [MR19](https://eprint.iacr.org/2019/706) for the Derandomization ("Correlated")
We use the notation from ROT^{κ,l} from [KOS15](https://eprint.iacr.org/2015/546)
for the protocol description (Figure 10). We apply the "Fiat-Shamir" heuristic,
replacing the coin tossing required for the consistency check with the
hash of the public transcript (using an (*) to denote the changes). We also
apply the "Forced Reuse" technique from [DKLs23](https://eprint.iacr.org/2023/765)
fixing one single batch of input choice bits (L=1) and reusing that batch
for all of the input batches.


## Protocol Description

**Players**: 2 parties, Sender (S) and Receiver (R)

**Parameters**:

- $\kappa$: a computational security parameter. We set $\kappa=128$ to align with the security of the ECC group.
- $\sigma$: a statistical security parameter. We set $\sigma=\kappa$ to align the statistical security with the computational security (fiat-shamir compliant).
- $\omega$: an expansion factor of the OTe batches. We set $\omega=2$ for DKLS23. Note that this parameter is implicit in the original protocol.
- $\xi$: the OTe batch size. We set $\xi=\kappa+2\sigma$ following the instructions in DKLS23.
- $LOTe$:  the number of $\xi\times\kappa$-bit OTe batches. We set $LOTe=1$ with "Forced Reuse" for DKLS23.
- $L$: the number of $\xi\times\omega$-scalar COTe input & output batches. $L=LOTe$ in general; $L > LOTe(=1)$ for "Forced Reuse" (as in DKLS23) such that $L$ is the number of reuses of a single OTe batch.
- $\eta$: the total OT expansion size. $\eta= LOTe \times\xi$ ( $\eta=\xi$ for "Forced Reuse").
- $\eta'$: the total OT expansion size with extra randomness for the consistency check. $\eta=L\times\xi+\sigma$ ( $\eta=\xi+\sigma$ for "Forced Reuse").



**Functionalities**:
- `BaseOT(κ)` Base Randomized Oblivious Transfer with $\kappa$ choice bits (e.g., $\mathsf{VSOT}$).
- `PRG(sid, x)` Collision-Resistant Pseudo Random Generator to expand $\kappa$ bits into $\eta'$ bits, input $x$ of size $\mathbb{Z}_2^\kappa$, output of size $\mathbb{Z}_2^{\eta'}$ (e.g., $\mathsf{TmmoHash}$).
- `Send(x)=> P` Send message x to party P.
- `t.Append(x)` Append message `x` to transcript `t`, and `t.Extract(n)` Extract `n` pseudo-random uniform bits from `t`.
- `ECS(x,ω)` Map x (a κ-bit word) uniformly to ω curve scalars (e.g., HashToField from [RFC9380](https://datatracker.ietf.org/doc/html/rfc9380)).

**Inputs**:
- R: $x \in \mathbb{Z}_2^\eta$, the choice bits. Just $[\xi]$ bits for "Forced Reuse"
- S: $\alpha \in \mathbb{Z}_q^{L\times\omega\times\xi}$ curve scalars as derandomization input.

**Outputs**:
- R: $z_B \in \mathbb{Z}_q^{L\times\omega\times\xi}$ curve scalars s.t. $z_A = x \cdot \alpha - z_B$
- S: $z_A \in \mathbb{Z}_q^{L\times\omega\times\xi}$ curve scalars s.t. $z_A = x \cdot \alpha - z_B$

## Protocol

0. **INIT**:
    1. Obtain a shared unique session id `sid` (e.g., with $\mathsf{AgreeOnRandom}$)
    2. Run `BaseOT(κ)`  with the roles reversed (i.e., the OTe sender is the BaseOT receiver and vice-versa), generating random 1|2-OT results to be used as seeds:
        - R: $(k^i_0, k^i_1) \in \mathbb{Z}_2^{2\times\kappa}\;\;\forall i \in [\kappa]$, the random OT input messages.
        - S: $(\Delta_i, k^i_{\Delta_i}) \in \mathbb{Z}_2^{(1+\kappa)}\;\;\forall i \in [\kappa]$, the BaseOT choice bits and chosen message.

1. **ROUND 1**, Receiver (R):
    1.	Extension (_Ext_)
        1.  Generate additional random choice bits.
            1. Sample $x_\sigma \in \mathbb{Z}_2^\sigma$, $\sigma$ random bits to be used for the consistency check.
            2.  Compute $x' = x || x_\sigma$, appending $\sigma$ random bits to the $\eta$ OTe choice bits, s.t. $x' \in \mathbb{Z}_2^{\eta'}$ 
        2.  Compute the seed expansions using the PRG salted with the $sid$.
            1. $t^i_0 = \mathsf{PRG}_{sid}(k^i_0) \;\forall i \in [\kappa]$
            2. $t^i_1 = \mathsf{PRG}_{sid}(k^i_1) \;\forall i \in [\kappa]$
        3. Compute $u^i = t^i_0 \oplus t^i_1 \oplus x_i \;\forall i \in [\kappa]$, the masking of the OTe batches.
    2. Consistency Check (_Check_)
        1. (*) Sample the random challenge $\chi$ with $M=\eta/\sigma$ words of $\sigma$ bits each --> We use Fiat-Shamir to replace the coin tossing, sampling the challenge from the transcript instead.
            1. Sample fresh randomness $r \in \mathbb{Z}_2^{\sigma\times\kappa}$.
            2. Append `t.Append(u, c)`, the previous message and the commit of fresh randomness to the transcript.
            3. Extract $\chi_j \in \mathbb{Z}_2^\sigma <--$`t.Extract(σ)` $\;\forall j \in [M]$, pseudo-random uniform bits from the transcript to serve as challenge.
        2. Compute the challenge response:
            1. $ẋ = x_{\eta:\eta+\sigma} + \sum_{j=1}^{M} \chi_j \cdot x_{j\sigma:(j+1)\sigma}$, the consistency check over the choice bits, with operations in $\mathbb{Z}_2$.
            2. $ṫ^i = t^i_{\eta:\eta+\sigma} + \sum_{j=1}^{M} \chi_j \cdot t^i_{j\sigma:(j+1)\sigma} \;\forall i \in [\kappa]$, the consistency checks over the OTe batches, with operations in $\mathbb{Z}_2$.
    3. Transpose & Randomize (_T&R_)
        1. Transpose $t_0$: $t^{i,j}_0 \rightarrow t^{j,i}_T \forall i \in [\kappa], \forall j \in [\eta] $.
        2. Compute $v_x^j = \mathsf{H}_{sid}(t^j_T)\;\forall j \in [\eta]$, the receiver OTe result.
    `R.Send(u, r, ẋ, ṫ)=> S`

2. **ROUND 2**, Sender (S):
    1.  Extension (_Ext_)
        1.  Compute $t^i_{\Delta_i} = \mathsf{PRG}_{sid}(k^i_{\Delta_i}) \;\forall i \in [\kappa]$, the seed expansions using the $\mathsf{PRG}$ salted with the $sid$.
        2.  Compute $q^i = \Delta_i \cdot u^i + t^i_{\Delta_i} \;\forall i \in [\kappa]$, the correlated masks of the OTe batches.
    2.  Consistency Check (_Check_)
        1. (*) Sample the random challenge $\chi$ with $M=\eta/\sigma$ words of $\sigma$ bits each using Fiat-Shamir.
            1. Append `t.Append(u, c)`, the previous message and the commit of fresh randomness to the transcript.
            2. Extract $\chi_j \in \mathbb{Z}_2^\sigma <--$`t.Extract(σ)` $\;\forall j \in [M]$, pseudo-random uniform bits from the transcript to serve as challenge.
        2. Compute $q̇^i = q^i_{\eta:\eta+\sigma} + \sum_{j=1}^{M} \chi_j \cdot q^i_{j\sigma:(j+1)\sigma} \;\forall i \in [\kappa]$, the expected challenge response.
        3. Abort if $q̇^i \neq ṫ^i + \Delta_i \cdot ẋ \;\forall i \in [\kappa]$.
    3.  Transpose & Randomize (_T&R_)
        1. Transpose $q$: $q^{i,j} \rightarrow q^{j,i}_T \forall i \in [\kappa], \forall j \in [\eta] $.
        2. Transpose $q+\Delta$: $(q+\Delta)^{i,j} \rightarrow (q+\Delta)^{j,i}_T \forall i \in [\kappa], \forall j \in [\eta] $.
        3. Compute $v_0^j = \mathsf{H}_{sid}(q^j_T)\;\forall j \in [\eta]$, $v_1^j = \mathsf{H}_{sid}((q+\Delta)^j_T)\;\forall j \in [\eta]$ as the sender OTe result.
    4. Derandomize (_Derand_)
        1. Compute $z_A^{j,k} = \mathsf{ECS}(v_0^{j}, \omega) \;\forall i \in [\kappa], \;\forall k \in [\omega]$, the sender COTe result.
        2. Compute $\tau^{j,k} = \mathsf{ECS}(v_1^{j}, \omega) - z_A^{j,k} + \alpha^{j,k} \;\forall i \in [\kappa], \;\forall k \in [\omega]$, the correlated masks of the COTe batches.
    
    `S.Send(τ)=> R`


3. **ROUND 3**, Receiver (R):
    1. Compute $z_B^{j,k} = x_j\cdot \tau^{j,k}   - \mathsf{ECS}(v_x^{j}, \omega) \;\forall i \in [\kappa], \;\forall k \in [\omega]$, the receiver COTe result.

## Best-effort Constant Time implementation

The code of this package is written in a best-effort mode to be Constant Time by: 
1. Removing data-dependent branching (e.g. if-else statements) and data-dependent iteration (e.g. data-dependent length of for-loops)
2. Using constant-time operations from primitives (e.g. constant-time field operations from `saferith`)
3. Delaying error/abort raising when tied to data (e.g., for loops in consistency checks) to avoid leaking unnecessary stop information. Note that this does not cover "static" errors (e.g., wrong size for hashing).
4. Using `crypto/subtle` functions whenever applicable.