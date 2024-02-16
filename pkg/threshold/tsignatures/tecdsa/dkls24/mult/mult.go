package mult

import (
	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
)

// These should really be parameters, but we are declaring them as constants for readability of struct field types.
const (
	// Commputational security parameter (a.k.a. lambda_c).
	Lambda      = base.ComputationalSecurity
	LambdaBytes = base.ComputationalSecurityBytes

	// Statistical security parameter (a.k.a. lambda_s).
	S      = base.ComputationalSecurity
	SBytes = S / 8

	// Group order bit-size (=|q| for group Zq).
	Kappa      = base.FieldBytes * 8
	KappaBytes = base.FieldBytes

	// Scalar batch size.
	L = 2

	// Expansion ratio, set to ceil(kappa / lambda_c) = 2.
	Rho = (Kappa + Lambda - 1) / Lambda

	// Number of OTe messages needed for the OTe functionality.
	LOTe = L + Rho

	// number of random choice bits per element in each batch.
	Xi      = Kappa + 2*S
	XiBytes = Xi / 8

	// OTe batch size.
	Eta      = Xi * L
	EtaBytes = Eta / 8
)

type (
	RvoleAliceInput = [L]curves.Scalar
	OutputShares    = [L]curves.Scalar
)

// Players: Alice (A) and Bob (B)
// Parameters:
// 	- lambda_c, computational security parameter (=128).
// 	- lambda_s, statistical security parameter (=128).       ---> No need to have it =128 in RVOLE (only necessary in OTE), DKLs24 sets it to 80 instead.
// 	- L, vector length
// 	- Kappa, =|q| for a group Z_q (=256)
// 	- Xi = kappa + 2 lambda_s (=512)
// 	- Rho = ceil(kappa / lambda_c) (=2)
// 	- g, a public gadget vector                                                            ---> Can be sampled by bob and reused, or  an AgreeOnRandom (just like another sessionId) and reused concurrently
// Functionalities:
// 	- OTE functionality for Xi batches with message length l_OT=L+Rho
// 	- H, a hash function to act as random oracle RO.
// Inputs:
// 	- sessionId, the session ID
// 	- A:  a (l elements in Zq)
// Outputs:
// 	- B: b (one element in Zq) ;   d (l elements in Zq)
// 	- A: c (l elements in Zq) s.t. a_i * b = c_i + d_i    for all i

// Protocol:

// 	B.Round1 a.k.a. "sample"/Sampling
// 		1. Sample beta ( l_OT bits)
// 		2. Compute b = sum_i (beta_i * g_i)
// 		3. Run OTE.Round1(beta) --> (...)
//         RETURN b

// 	A.Round2 a.k.a. "multiply"
// 		1. Run  OTE.Round2(...) --> alpha_0, alpha_1, (...)
// 		2. c_i = - sum_j (g_j * alpha_0_j)   for all i in [l] ---> his output!
// 		3. ahat <- Zq^rho
// 		4. for i in [l]:
// 			4.1. atilde_i = a_i + alpha_0_j  - alpha_1_j
// 		5. for k in [rho]:
// 			5.1. atilde_{l+k} = ahat_k + alpha_0_{l+k} - alpha_1_{l+k}
// 		6. theta <- H_Zq(sessionId || atilde) of length l*rho
// 			NOTE (not in spec): Hash2Field is required for this step. This can be achieved in a single call to Hash2Field by concatenating the atilde_i's and then hashing the result.
// 		7. for k in [rho]:
// 			7.1. eta_k = ahat_k + sum_i^l (theta_{i*rho + k} * a_i)
// 		8. for j in [Xi]:
// 			8.1. mubold_j = sum_k^rho (alpha_0_{j,l+k} + sum_i^l (theta_{i*rho + k} * alpha_0_{j,i}))
// 		9. Mu = H (sessionId || mubold) of length 2*lambda_c
// 			NOTE: This can be achieved directly with a variable length hash function.
// 		10. Send(atilde, eta, Mu) to B
//         RETURN c

// 	B.Round3(atilde, eta, Mu)
//         1. Run OTE.Round3(...) --> gamma
// 		2. theta <- H_Zq(sessionId || atilde) of length l*rho
//         3. for j in [Xi]:
//             3.1 ddot_{j,i} = gamma_j,i + beta_j * atilde_{j,i}  for all i in [l]
//             3.2 dhat_{j,k} = gamma_{j,l+k} + beta_j * ahat_{j,k}  for all k in [rho]
//             3.3 muBoldPrime_{j,k} = dhat_{j,k} - beta_j * eta_k + sum_i^l (theta_{i*rho + k} * ddot_{j,i})  for all k in [rho]
//         4. muPrime = H (sessionId || muBoldPrime) of length 2*lambda_c
//         5. Check if muPrime == Mu, ABORT otherwise
//         6. Compute d_i = sum_j (g_j * ddot_{j,i})  for all i in [l]
//         RETURN d
