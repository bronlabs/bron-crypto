This package implements the two-party OT-based multiplication protocol that is used inside DKLs23, originating from DKLs19.

A two-party multiplication protocol between Alice and Bob is a protocol resulting in additive shares of the multiplication of Alice and Bob's secrets. In other words, Let `a` be Alice's secret and `b` be Bob's secret. The protocol outputs `α` to Alice and `β` to Bob such that `a+b=α*β`.

The protocol we've implemented has the following properties is batched ie. It allows parallel multiplication of `L` many inputs from Alice and Bob.

Trivially, by providing random values as `a` and/or `b`, this protocol becomes a randomized multiplication protocol.

Note that in DKLs23, a particular variant of this protocol is used that is called "Forced Reuse". Effectively, Bob has a single random input equal to his pad and Alice has two non-random inputs. The output of the protocol is multiplication of Bob's single input to the vector of Alice's inputs. As a consequence, this protocol will have one fewer rounds than the original version described in DKLs19.

What we've implmeneted, is forced reuse variant of this multiplication protocol with L=2. Note that this means this is a randomized multiplication protocol since Bob's input will be randomized.


The details of the main protocol is sketched in Protocol 1 of DkLs19 and the necessary modifications to this protocol for DKLs23 is described in Functionality 3.5 of DKLs23.

Below, we'll provide the specification of what we'll implement.



// ------------------------------ PROTOCOL 2Pmul ---------------------------- //
// PLAYERS: 2 parties, A (Alice) and B (Bob).
//
// PARAMS:
// # κ (kappa), a computational security parameter, κ = |q| (for a field ℤq). E.g. κ=256
// # s, a statistical security parameter. E.g. s=128
// # ξ (Xi), the COTe input batch size, set to ξ=κ+2s.
// # L ∈ ℕ, the DKLs23 batch size in #elements (not to mistake with batch size l=1 of DKLs19).
// # g, public gadget vector (sampled from ℤq^ξ). E.g. g = (g_1, ..., g_η) where g_i ∈ ℤq

// FUNCTIONALITIES:
//  `SampleZq(k)`   Cryptographically secure sampling of k random elements in ℤq
//  `SampleBits(k)` Cryptographically secure sampling of k random bits
//  `COTe(η)` Correlated Oblivious Transfer with η choice bits.
//  `H(x,L)` Hash function, input x of variable size, output of size ℤq^L
//  `Send(x)=> P` Send message x to party P.
//
// INPUTS:
// # A-> a ∈ ℤq^L, the input vector of Alice.
// # B-> b ∈ ℤq, the input element of Bob
//
// OUTPUTS:
// # A-> z_B ∈ ℤq^L, the correlation of Alice s.t. z_A + z_B = a • b
// # B-> z_A ∈ ℤq^L, the correlation of Bob   s.t. z_A + z_B = a • b
// -------------------------------------------------------------------------- //
//
// STEPS I/O:
//  B: b ------(SAMPLING)------> A: z_A
//  A: a ---(MULTIPLICATION)---> B: z_B
//
// PROTOCOL STEPS:
//
//	# INIT:
//	  (1). Compute COTe.Setup (init S&R in SoftspokenOT with [κ × BaseOT] seeds)
//
//  # SAMPLING:
//	  (2). Bob samples random choice bits β and defines a pad b̃
//       B: β = SampleBits(ξ)                                           ∈ [ξ]bits
//	        b̃ = Σ{j=0}^{ξ-1} g_j • β_j                                  ∈ ℤq
//    (3). Alice samples pads ã and check values â
//       A: ã = SampleZq(L)                                             ∈ [L]ℤq
//          â = SampleZq(L)                                             ∈ [L]ℤq
//        // Each of the L OTe batches of size ξ correlates OTeWidth=2 scalars
//        // Replicate ξ times the elements of ã and â inside each of the L batches
//          α = {{ã_1, â_1}, || {{ã_2, â_2},  || ... || {{ã_L, â_L},    ∈ [L][ξ][2]ℤq
//               {ã_1, â_1},     {ã_2, â_2},  || ... ||  {ã_L, â_L},
//               {..., ...},     {..., ...},  || ... ||  {..., ...},
//               {ã_1, â_1}}     {ã_2, â_2}}  || ... ||  {ã_L, â_L}}
//    (4). Alice and Bob jointly compute COTe (2 Rounds of comm.)       ∈ [L][ξ][2]ℤq
//       A: α ---┐                  ┌---> A: z_A                        ∈ [L][ξ][2]ℤq
//               ├--- COTe_{κ, L}---┤       s.t. z_A = x • α - z_B
//       B: β ---┘                  └---> B: z_B                        ∈ [L][ξ][2]ℤq
//	      // Split the COTe output in two vectors of size ξ*L
//       A: z̃_A = z_A[:][:][0]    // Every first element                ∈ [L][ξ]ℤq
//          ẑ_A = z_A[:][:][1]    // Every other element                ∈ [L][ξ]ℤq
//       B: z̃_B = z_B[:][:][0]    // Every first element                ∈ [L][ξ]ℤq
//          ẑ_B = z_B[:][:][1]    // Every other element                ∈ [L][ξ]ℤq
//    (5). Alice and Bob generate a challenge using the transcript of COTe
//       A: χ1 = H(1||COTe.S.transcript, L)                             ∈ [L]ℤq
//          χ2 = H(2||COTe.S.transcript, L)                             ∈ [L]ℤq
//       B: χ1 = H(1||COTe.R.transcript, L)                             ∈ [L]ℤq
//          χ2 = H(2||COTe.R.transcript, L)                             ∈ [L]ℤq
//    (6). Alice computes the challenge response and sends it
//       A: r_{i,j} = χ1_i • z̃_A_{iξ+j} + χ2_i • ẑ_A_{iξ+j}             ∈ ℤq ∀i∈[L] ∀j∈[ξ]
//          u_i = χ1_i • ã_i + χ2_i • â_i                               ∈ ℤq ∀i∈[L]
//         // We follow this optimization of DKLs23 (page 31) based on the RO model
//          r̃_A = H(r, 1)                                               ∈ ℤq
//          Send(r̃,u)=>B
//    (7). Bob validates the challenge response
//       B: r_{i,j} = β_j•u_i - χ1_i•z̃_B_{iξ+j} - χ2_i•ẑ_B_{iξ+j}       ∈ ℤq ∀i∈[L] ∀j∈[ξ]
//         // We follow this optimization of DKLs23 (page 31) based on the RO model
//          r̃_B = H(r, 1)                                               ∈ ℤq
//          ABORT if r̃_A ≠ r̃_B
//    (9a). Alice computes her correlation based on γ_B = 0 (only in DKLs23)
//       A: z_A_i = Σ{j=1}^{ξ} g_j • z̃_A_{iξ+j}                         ∈ ℤq ∀i∈[L]
//          z_A = z_A + z_A_i                                           ∈ ℤq^L
//
//  # MULTIPLICATION:
//    (8). Alice sets her derandomization mask and sends it to Bob:
//       A: γ_A_i = a_i - ã_i                                           ∈ ℤq ∀i∈[L]
//          Send(γ_A)=>B                                                ∈ [L]ℤq
//    (9b). Bob computes his correlation based on γ_A
//       B: z_B_i = b̃•γ_A_i + Σ{j=1}^{ξ} g_j•z̃_B_{iξ+j}               ∈ ℤq ∀i∈[L]
//
// -------------------------------------------------------------------------- //
// ========================================================================== //
// -------------------------------------------------------------------------- //
// ROUNDS (SEPARATE SAMPLING & MULTIPLICATION):
//                                                              Step numbers
//  0. Setup           R & S:(...) ---(κ × BaseOT)--->(...)     [1]
//  1-3. Sampling:     B: b ------(SAMPLING)------> A: z_A      [2-7,9a]
//  4. Multiplication: A: a ---(MULTIPLICATION)---> B: z_B      [8,9b]
// -------------------------------------------------------------------------- //
// ROUNDS (OPTIMIZED, MERGE SEND IN (6) and in (8)):
//                                                              Step numbers
//  0. Setup           R & S:(...) ---(κ × BaseOT)--->(...)     [1]
//  1-2. Sampling:     B: b ------(SAMPLING)------> A: z_A      [2,3,4,5,9a]
//  3. Multiplication: A: a ---(MULTIPLICATION)---> B: z_B      [6,7,8,9b]
// -------------------------------------------------------------------------- //

