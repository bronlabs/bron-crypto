package softspoken

// ------------------------------ PROTOCOL F_COTe --------------------------- //
// PLAYERS: 2 parties, R (receiver) and S (sender).
//
// PARAMS:
// # κ (kappa), a computational security parameter. E.g. κ=256
// # ξ, a bit-level batch size. ξ=L_ote*κ for a chosen L_ote ∈ ℕ. ξ'=ξ+σ. L_ote=1 for DKLS23.
// # σ (sigma), a statistical security parameter. ξ%σ=0. E.g. σ=128
//
// INPUTS:
// # R-> x ∈ [ξ]bits, the Choice bits.
// # S-> α ∈ [ξ]group, the InputOpt.
//
// OUTPUTS:
// # R-> z_B ∈ [ξ]group, the Correlation    s.t. z_A = x • α - z_B
// # S-> z_A ∈ [ξ]group, the DeltaOpt       s.t. z_A = x • α - z_B
//
// PROTOCOL STEPS:
//
//	# A base OT protocol to generate random 1|2-OT results to be used as seeds:
//	  [κ × BaseOT]  (NOTE! The BaseOT roles are reversed w.r.t. the OTe roles)
//	  ├---->R: (k^i_0, k^i_1)                                         ∈ [2]×[κ]bits   ∀i∈[κ]
//	  └---->S: (Δ_i, k^i_{Δ_i})                                       ∈ 1 + [κ]bits   ∀i∈[κ]
//	# Seeding a PRG with the BaseOT Options to extend them:
//	  (Ext.1)   R: sample(x_i) ∈ [ξ']bits. Can come from Fiat-Shamir heuristic (*).
//	  (Ext.2)   R: t^i_0, t^i_1 = PRG(k^i_0), PRG(k^i_1)              ∈ [2]×[ξ']bits  ∀i∈[κ]
//	  .         S: t^i_{Δ_i}    = PRG(k^i_{Δ_i})                      ∈ [ξ']bits      ∀i∈[κ]
//	  (Ext.3)   R: u^i = t^i_0 ⊕ t^i_1 ⊕ x_i                          ∈ [ξ']bits      ∀i∈[κ]
//	  .            Send(u) => S                                       ∈ [ξ']×[κ]bits
//	  (Ext.4)   S: q^i = Δ_i • u^i + t^i_{Δ_i}                        ∈ [ξ']bits      ∀i∈[κ]
//	# A bit-level correlation used to check the extension consistency.
//	  (Check.1) S: sample(χ_i)                                        ∈ [σ]bits       ∀i∈[M]
//	  .            Send(χ) => R                                       ∈ [σ]×[M]bits
//	  (Check.2) R: x_val = x̂_{m} + Σ{j=0}^{m-1} χ_j • x_hat_j         ∈ [σ]bits
//	  .                        └---where x^hat_j = x_{σj:σ(j+1)}
//	  .            t_val^i = t^i_hat_{m} + Σ{j=0}^{m-1} χ_j•t^i_hat_j ∈ [σ]bits       ∀i∈[κ]
//	  .                        └---where t^i_hat_j = t^i_{σj:σ(j+1)}
//	  .            Send(x_val, t_val^i) => S                          ∈ [σ] + [σ]×[κ]bits
//	  (Check.3) S: q_val^i = q^i_hat_{m} + Σ{j=0}^{m-1} χ_j•q^i_hat_j ∈ [σ]bits       ∀i∈[κ]
//	  .                        └---where q^i_hat_j = q^i_{σj:σ(j+1)}
//	  .            ABORT if  q_val^i != t_val^i + Δ_i • x_val         ∈ [σ]bits       ∀i∈[κ]
//	# A bit-level randomization to destroy the bit-level correlation.
//	  (T&R.1)   R: transpose(t^i_0) ->t_j                             ∈ [κ]bits       ∀j∈[ξ']
//	  .         S: transpose(q^i) -> q_j                              ∈ [κ]bits       ∀j∈[ξ']
//	  (T&R.2)   R: v_x = Hash(j || t_j)                               ∈ [κ]bits       ∀j∈[ξ]
//	  (T&R.3)   S: v_0 = Hash(j || q_j)                               ∈ [κ]bits       ∀j∈[ξ]
//	  .         S: v_1 = Hash(j || (q_j + Δ) )                        ∈ [κ]bits       ∀j∈[ξ]
//	# A field-level correlation to obtain the COTe result.
//	  (Derand.1) S: z_A_j = ECP(v_0_j)                                ∈ curve.Scalar  ∀j∈[ξ]
//	  .             τ_j = ECP(v_1_j) - z_A_j + α_j                    ∈ curve.Scalar  ∀j∈[ξ]
//	  .                    └---where ECP(v) is the mapping of v to the curve
//	  .            Send(τ) => R                                       ∈ [ξ]curve.Scalar
//	  (Derand.2) R: z_B_j = τ_j - ECP(v_x_j)  if x_j == 1             ∈ curve.Scalar  ∀j∈[ξ]
//	  .                   =     - ECP(v_x_j)  if x_j == 0
//
// -------------------------------------------------------------------------- //
// ========================================================================== //
// -------------------------------------------------------------------------- //
// ROUNDS (COTe):
//
//  0. Setup R & S:(...) ---(κ × BaseOT)--->(...)     [BaseOT]
//  1. R: (x) 		---(Round1)--->(u, v_x)           [Ext.1, Ext.2, Ext.3]
//  2. S: (α) 		---(Round2)--->(χ, τ, z_B)        [Ext.2, Ext.4, Check.1, T&R.1, T&R.3, Derand.1]
//  3. R: (χ, τ) 	---(Round3)--->(x_val, t_val, z_A)[Check.2, T&R.1, T&R.2, Derand.2]
//  3+.S: (x_val, t_val) ---(Round3+)--->()           [Check.3]

// -------------------------------------------------------------------------- //
// ROUNDS (COTe with fiat-shamir (*)):
//
//  0. Setup R & S:(...) ---(κ × BaseOT)--->(...)  [BaseOT]
//  1. R: (x)---(Round1)--->(u, x_val, t_val) 	   [Ext.1, Ext.2, Ext.3, Check.1*, Check.2, T&R.1, T&R.2]
//  2. S: (u,x_val,t_val,α)---(Round2)--->(τ, z_B) [Ext.1, Ext.2, Ext.4, T&R.1, T&R.3, Derand.1, Check.1*, Check.3]
//  2+.R: (τ)---(Round3)--->(z_A)			   	   [Derand.2]

// -------------------------------------------------------------------------- //
// ROUNDS (OTe):
//
//  0. Setup R & S:(...) ---(κ × BaseOT)--->(...)  [BaseOT]
//  1. R: (x) ---(Round1)--->(u, v_x)              [Ext.1, Ext.2, Ext.3]
//  2. S: (u) ---(Round2)--->(χ, v_0, v_1)         [Ext.2, Ext.4, Check.1, T&R.1, T&R.3]
//  3. R: (χ) ---(Round3)--->(x_val, t_val)	       [Check.2, T&R.1, T&R.2]
//  3+. S: (x_val, t_val) ---(Round3+)--->()       [Check.3]
// -------------------------------------------------------------------------- //
// ROUNDS (OTe with fiat-shamir (*)):
//
//  0. Setup R & S: (...)---(κ × BaseOT)--->(...)  [BaseOT]
//  1. R: (x)---(Round1)--->(u, v_x, x_val, t_val) [Ext.1, Ext.2, Ext.3, Check.1*, Check.2, T&R.1, T&R.2]
//  1+.S: (u,x_val, t_val)---(Round2)--->(v_0, v_1)[Ext.1, Ext.2, Ext.4, Check.1*, T&R.1, T&R.3, Check.3]
