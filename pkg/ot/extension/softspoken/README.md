# Softspoken OT Extension
Package softspoken implements of maliciously secure 1-out-of-2 Correlated Oblivious Transfer extension (COTe) protocol.

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

```golang

/*
// ============================= FUNCTIONALITIES ============================ //
OBLIVIOUS TRANSFER (OT)
At high level, a single 1-out-of-2 OT realizes this functionality:
┌------┐                      ┌------------------┐               ┌--------┐
|      |                      |                  |               |        |
|      |--> (Opt_0, Opt_1) -->|      1|2  OT     | <--(Choice)<--|        |
|Sender|                      |                  |               |Receiver|
|      |                      └------------------┘               |        |
|      |                               └-------> (DeltaOpt) -->  |        |
└------┘                                                         └--------┘
s.t. DeltaOpt = Opt_{Choice} = Opt_0 • (1-Choice) + Opt_1 • Choice

RANDOMIZED OBLIVIOUS TRANSFER (ROT)
Instead, a Randomized OT randomly picks the Sender's input Options:
┌------┐                      ┌------------------┐               ┌--------┐
|      |                      |                  |               |        |
|      |                      |      1|2 ROT     | <--(Choice)<--|        |
|Sender|                      |                  |               |Receiver|
|      |                      └------------------┘               |        |
|      | <----- (Opt_0, Opt_1) <--------┴-------> (DeltaOpt) --> |        |
└------┘                                                         └--------┘
s.t. DeltaOpt = Opt_{Choice} = Opt_0 • (1-Choice) + Opt_1 • Choice

CORRELATED OBLIVIOUS TRANSFER (COT)
In contrast, a single "Correlated" OT realizes tbe following functionality:
┌------┐                      ┌------------------┐               ┌--------┐
|      |                      |                  |               |        |
|      |----> (InputOpt) ---->|      1|2  COT    | <--(Choice)<--|        |
|Sender|                      |                  |               |Receiver|
|      |                      └------------------┘               |        |
|      | <----- (Correlation) <--------┴-------> (DeltaOpt) ---> |        |
└------┘                                                         └--------┘
s.t. Correlation = Choice • InputOpt - DeltaOpt
The Options, DeltaOpt and Correlation are elements of a group (e.g. Z_2,
Z_{2^N}, F_q, elliptic curve points), whereas Choice is always a bit.
OT EXTENSION (OTe, COTe)
An "Extension" (both for OT and COT with Options of length κ) makes use of a
PRG to expand each block of κ Base OTs  into L = n*κ OTs.

// ============================= PROTOCOL F_COTe ============================ //
PLAYERS: 2 parties, R (receiver) and S (sender).

PARAMS:
# κ (kappa), a computational security parameter. E.g. κ=256
# ξ, a bit-level OTe batch size. ξ=𝒪(κ,...) --> ξ=κ+2s for DKLS23.
# σ (sigma), a statistical security parameter. ξ%σ=0. E.g. σ=128.
# L, the number of ξ-bit batches after in the expansion. L=1 For "Forced Reuse" (as in DKLS23).
# L', the number of ξ-scalar COTe input & output batches. L'=L in general,
#     L' > L(=1) for "Forced Reuse" such that L'/L is the # of reuses of the single OTe batch.
# η (eta), OT expansion size without the statistical redundancy. η=L*ξ (η=ξ for "Forced Reuse").
# η' (etaPrime), the full OT expansion size. η=L*ξ+σ (η=ξ+σ for "Forced Reuse").
# ω (omega), a field-level expansion factor at the derandomization. E.g., ω=2 for DKLS23.

INPUTS:
# R-> x ∈ [η] bits, the Choice bits. (just [ξ] bits for "Forced Reuse")
# S-> α ∈ [L'][ω][ξ]curve.Scalar, the InputOpt.

OUTPUTS:
# R-> z_B ∈ [L'][ω][ξ]group, the Correlation    s.t. z_A = x • α - z_B
# S-> z_A ∈ [L'][ω][ξ]group, the DeltaOpt       s.t. z_A = x • α - z_B

PROTOCOL STEPS:
# A base OT protocol to generate random 1|2-OT results to be used as seeds:

	[κ × BaseOT]  (NOTE! The BaseOT roles are reversed w.r.t. the OTe roles)
	├---->R: (k^i_0, k^i_1)                                         ∈ [2]×[κ]bits   ∀i∈[κ]
	└---->S: (Δ_i, k^i_{Δ_i})                                       ∈ 1 + [κ]bits   ∀i∈[κ]

# Seeding a PRG with the BaseOT Options to extend them (L=1 & η'=ξ+σ for "Forced Reuse")

	(Ext.1)   R: sample(x_i), ∈ [η'-η]bits, append to x ∈ [η']bits  ∈ [η']bits
	(Ext.2)   R: t^i_0, t^i_1 = PRG(k^i_0), PRG(k^i_1)              ∈ [2]×[η']bits  ∀i∈[κ]
	.         S: t^i_{Δ_i}    = PRG(k^i_{Δ_i})                      ∈ [η']bits      ∀i∈[κ]
	(Ext.3)   R: u^i = t^i_0 ⊕ t^i_1 ⊕ x_i                          ∈ [η']bits      ∀i∈[κ]
	.            Send(u) => S                                       ∈ [η']×[κ]bits
	(Ext.4)   S: q^i = Δ_i • u^i + t^i_{Δ_i}                        ∈ [η']bits      ∀i∈[κ]

# A bit-level correlation used to check the extension consistency.

	(Check.1) S: sample(χ_i) ((*) from transcript in Fiat-Shamir)   ∈ [σ]bits       ∀i∈[M]
	.            Send(χ) => R                                       ∈ [σ][M]bits
	(Check.2) R: ẋ = x̂_{m+1} + Σ{j=1}^{m} χ_j • x_hat_j             ∈ [σ]bits
	.                        └---where x̂_j = x_{σj:σ(j+1)}
	.            ṫ^i = t^i_hat_{m+1} + Σ{j=1}^{m} χ_j•t^i_hat_j     ∈ [σ]bits       ∀i∈[κ]
	.                        └---where t^i_hat_j = t^i_{σj:σ(j+1)}
	.            Send(ẋ, ṫ^i) => S                                  ∈ [σ] + [κ]×[σ]bits
	(Check.3) S: q̇^i = q^i_hat_{m} + Σ{j=0}^{m-1} χ_j•q^i_hat_j     ∈ [σ]bits       ∀i∈[κ]
	.                        └---where q^i_hat_j = q^i_{σj:σ(j+1)}
	.            ABORT if  q̇^i != ṫ^i + Δ_i • ẋ                     ∈ [σ]bits       ∀i∈[κ]

# A bit-level randomization to destroy the bit-level correlation. (L=1 for "Forced Reuse")

	(T&R.1)   R: transpose(t^i_0) ->t_j                             ∈ [κ]bits       ∀j∈[η']
	.         S: transpose(q^i) -> q_j                              ∈ [κ]bits       ∀j∈[η']
	(T&R.2)   R: v_x = Hash(j || t_j)                               ∈ [ω]×[κ]bits   ∀j∈[L][ξ]
	(T&R.3)   S: v_0 = Hash(j || q_j)                               ∈ [ω]×[κ]bits   ∀j∈[L][ξ]
	.         S: v_1 = Hash(j || (q_j + Δ))                         ∈ [ω]×[κ]bits   ∀j∈[L][ξ]

# A field-level correlation to obtain the COTe result. (L' > L(=1) for "Forced Reuse", L'=L otherwise)

	(Derand.1) S: z_A_j = ECP(v_0_j)                                ∈ curve.Scalar  ∀j∈[ξ] ∀k∈[ω] ∀[L']
	.             τ_j = ECP(v_1_j) - z_A_j + α_j                    ∈ curve.Scalar  ∀j∈[ξ] ∀k∈[ω] ∀[L']
	.                    └---where ECP(v) is the mapping of v to the curve
	.            Send(τ) => R                                       ∈ [L][ω][ξ]curve.Scalar
	(Derand.2) R: z_B_j = τ_j - ECP(v_x_j)  if x_j == 1             ∈ curve.Scalar  ∀j∈[ξ] ∀k∈[ω] ∀[L']
	.                   =     - ECP(v_x_j)  if x_j == 0

// ============================ PROTOCOL ROUNDS ============================= //
// -------------------------------------------------------------------------- //
ROUNDS (COTe):
 0. Setup R & S:(...) ---(κ × BaseOT)--->(...) [BaseOT]
 1. R: (x)------(Round1)--->(u,v_x)            [Ext.1, Ext.2, Ext.3]
 2. S: (α)------(Round2)--->(χ,τ,z_B)          [Ext.2, Ext.4, Check.1, T&R.1, T&R.3, Derand.1]
 3. R: (χ,τ)----(Round3)--->(ẋ,ṫ,z_A)          [Check.2, T&R.1, T&R.2, Derand.2]
 4. S: (ẋ,ṫ)----(Round4)--->()                 [Check.3]

// -------------------------------------------------------------------------- //
ROUNDS (COTe with fiat-shamir (*)):
 0. Setup R & S:(...) ---(κ × BaseOT)--->(...) [BaseOT]
 1. R: (x)---------(Round1)--->(u,ẋ,ṫ)         [Ext.1, Ext.2, Ext.3, Check.1*, Check.2, T&R.1, T&R.2]
 2. S: (u,ẋ,ṫ,α)---(Round2)--->(τ,z_B)         [Ext.1, Ext.2, Ext.4, T&R.1, T&R.3, Derand.1, Check. Check.3]
 3. R: (τ)---------(Round3)--->(z_A)           [Derand.2]

// -------------------------------------------------------------------------- //
ROUNDS (ROTe):
 0. Setup R & S:(...) ---(κ × BaseOT)--->(...) [BaseOT]
 1. R: (x) -----(Round1)--->(u, v_x)           [Ext.1, Ext.2, Ext.3]
 2. S: (u) -----(Round2)--->(χ, v_0, v_1)      [Ext.2, Ext.4, Check.1, T&R.1, T&R.3]
 3. R: (χ) -----(Round3)--->(ẋ, ṫ)             [Check.2, T&R.1, T&R.2]
 4. S: (ẋ,ṫ) ---(Round4)--->()                 [Check.3]

// -------------------------------------------------------------------------- //
ROUNDS (ROTe with fiat-shamir (*)):
 0. Setup R & S: (...)---(κ × BaseOT)--->(...) [BaseOT]
 1. R: (x)-------(Round1)--->(u,v_x,ẋ,ṫ)       [Ext.1, Ext.2, Ext.3, Check.1*, Check.2, T&R.1, T&R.2]
 2. S: (u,ẋ,ṫ)---(Round2)--->(v_0,v_1)         [Ext.1, Ext.2, Ext.4, Check.1*, T&R.1, T&R.3, Check.3]
*/
```