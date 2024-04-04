package dkls23

import (
	"crypto/subtle"
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	"github.com/copperexchange/krypton-primitives/pkg/ot"
)

func (bob *Bob) Round1() (b curves.Scalar, r1out *Round1Output, err error) {
	// Validation
	if bob.Round != 1 {
		return nil, nil, errs.NewRound("Running round %d but bob expected round %d", 1, bob.Round)
	}

	// step 1.1: Sample β ∈ [ξ]bits
	bob.Beta = make(ot.PackedBits, XiBytes)
	if _, err := io.ReadFull(bob.Prng, bob.Beta); err != nil {
		return nil, nil, errs.WrapRandomSample(err, "bob could not sample beta")
	}

	// step 1.2: Run OTE.Round1(β) ---> γ ∈ ℤq^[ξ]
	OTeReceiverOut, r1out, err := bob.receiver.Round1(bob.Beta)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "bob step 1.3")
	}
	for j := 0; j < Xi; j++ {
		for l := 0; l < LOTe; l++ {
			bob.Gamma[j][l], err = bob.Protocol.Curve().Scalar().ScalarField().Hash(OTeReceiverOut[j][l][:])
			if err != nil {
				return nil, nil, errs.WrapHashing(err, "bob could not hash to gamma")
			}
		}
	}

	bob.Beta = bob.Beta.Unpack() // unpack beta for easier access to individual bits

	// step 1.3: b = ∑_{j∈[ξ]} β_j * g_j
	b = bob.Protocol.Curve().Scalar().ScalarField().Zero()
	for j := 0; j < Xi; j++ {
		b = bob.Protocol.Curve().Scalar().ScalarField().Select(bob.Beta[j] != 0, b, b.Add(bob.gadget[j]))
	}

	bob.Round = 3
	return b, r1out, nil
}

func (alice *Alice) Round2(r1out *Round1Output, a RvoleAliceInput) (c *OutputShares, r2o *Round2Output, err error) {
	// Validation, r1out and a delegated to OTE.Round2
	if alice.Round != 2 {
		return nil, nil, errs.NewRound("Running round %d but alice expected round %d", 2, alice.Round)
	}
	for i, a_i := range a {
		if a_i == nil {
			return nil, nil, errs.NewIsNil("a[%d]", i)
		}
	}

	C := new(OutputShares)
	scalarField := alice.Protocol.Curve().Scalar().ScalarField()

	// step 2.1: Run OTE.Round2(...) --> (α0_j, α1_j) ∈ ℤq^[LOTe]   ∀j∈[ξ]
	alphaBits, err := alice.sender.Round2(r1out)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "alice cote round 2")
	}
	var alpha0, alpha1 [Xi][LOTe]curves.Scalar
	for j := 0; j < Xi; j++ {
		for l := 0; l < LOTe; l++ {
			alpha0[j][l], err = scalarField.Hash(alphaBits[j][0][l][:])
			if err != nil {
				return nil, nil, errs.WrapHashing(err, "could not hash to alpha0j")
			}
			alpha1[j][l], err = scalarField.Hash(alphaBits[j][1][l][:])
			if err != nil {
				return nil, nil, errs.WrapHashing(err, "could not hash to alpha1j")
			}
		}
	}

	// step 2.2: C_i = ∑_{j∈[ξ]} α_0_j * g_j   ∀i∈[𝓁]
	for i := 0; i < L; i++ {
		C[i] = scalarField.Zero()
		for j := 0; j < Xi; j++ {
			C[i] = C[i].Sub(alice.gadget[j].Mul(alpha0[j][i]))
		}
	}

	// step 2.3: Sample â ∈ ℤq^[ρ]
	var aHat [Rho]curves.Scalar
	for k := 0; k < Rho; k++ {
		aHat[k], err = scalarField.Random(alice.Prng)
		if err != nil {
			return nil, nil, errs.WrapRandomSample(err, "alice failed to sample a hat")
		}
	}

	// step 2.4: ã_j = { { α0_{j,i} - α1_{j,i} + a_i }_{i∈[𝓁]} ||
	//                 { { α0_{j,l+k} - α1_{j,l+k} + â_i }_{k∈[ρ]} }  ∀j∈[ξ]
	var aTilde [Xi][LOTe]curves.Scalar
	aTildeBytes := make([]byte, 0, (Xi * LOTe * base.FieldBytes))
	for j := 0; j < Xi; j++ {
		for i := 0; i < L; i++ {
			aTilde[j][i] = a[i].Add(alpha0[j][i]).Sub(alpha1[j][i])
			aTildeBytes = append(aTildeBytes, aTilde[j][i].Bytes()...)
		}
		for k := 0; k < Rho; k++ {
			aTilde[j][L+k] = aHat[k].Add(alpha0[j][L+k]).Sub(alpha1[j][L+k])
			aTildeBytes = append(aTildeBytes, aTilde[j][L+k].Bytes()...)
		}
	}

	// step 2.5: θ <--- H_{ℤq^{𝓁xρ}} (sessionId || ã)
	theta, err := alice.Protocol.Curve().HashToScalars(L*Rho, alice.SessionId, aTildeBytes)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not hash to theta")
	}

	// step 2.6: η_k = â_k + ∑_{i∈[𝓁]} θ_{i*ρ + k} * a_i  ∀k∈[ρ]
	var eta [Rho]curves.Scalar
	for k := 0; k < Rho; k++ {
		eta[k] = aHat[k]
		for i := 0; i < L; i++ {
			eta[k] = eta[k].Add(theta[i*Rho+k].Mul(a[i]))
		}
	}

	// step 2.7: μb_{j,k} = α0_{j,l+k} + ∑_{i∈[𝓁]} θ_{i*ρ + k} * α0_{j,i}  ∀k∈[ρ]  ∀j∈[ξ]
	muBytes := make([]byte, 0, (Xi * Rho * base.FieldBytes))
	for j := 0; j < Xi; j++ {
		for k := 0; k < Rho; k++ {
			muBold_j_k := alpha0[j][L+k]
			for i := 0; i < L; i++ {
				muBold_j_k = muBold_j_k.Add(theta[i*Rho+k].Mul(alpha0[j][i]))
			}
			muBytes = append(muBytes, muBold_j_k.Bytes()...)
		}
	}

	// step 2.8: μ = H_{ℤ2^{2*λ_c}} (sessionId || μb)
	mu, err := hashing.Hash(base.RandomOracleHashFunction, alice.SessionId, muBytes)
	if err != nil {
		return nil, nil, errs.WrapHashing(err, "could not hash to mu")
	}

	alice.Round++
	return C, &Round2Output{ATilde: aTilde, Eta: eta, Mu: mu}, nil
}

func (bob *Bob) Round3(r2out *Round2Output) (D *[L]curves.Scalar, err error) {
	// Validation
	if bob.Round != 3 {
		return nil, errs.NewRound("Running round %d but bob expected round %d", 3, bob.Round)
	}
	if err := r2out.Validate(bob.Protocol); err != nil {
		return nil, errs.WrapValidation(err, "wrong round 3 input")
	}

	scalarField := bob.Protocol.Curve().Scalar().ScalarField()
	D = new([L]curves.Scalar)
	for i := 0; i < L; i++ {
		D[i] = scalarField.Zero()
	}

	// step 3.1: θ <--- H_{ℤq^{𝓁xρ}} (ã || sessionId)
	aTildeBytes := make([]byte, 0, ((L + Rho) * Xi * base.FieldBytes))
	for j := 0; j < Xi; j++ {
		for i := 0; i < L; i++ {
			aTildeBytes = append(aTildeBytes, r2out.ATilde[j][i].Bytes()...)
		}
		for k := 0; k < Rho; k++ {
			aTildeBytes = append(aTildeBytes, r2out.ATilde[j][L+k].Bytes()...)
		}
	}
	theta, err := bob.Protocol.Curve().HashToScalars(L*Rho, bob.SessionId, aTildeBytes)
	if err != nil {
		return nil, errs.WrapFailed(err, "bob could not hash to theta")
	}

	var ddot_j [L]curves.Scalar
	var dhat_j_k, muBoldPrime_j_k curves.Scalar
	muPrimeBytes := make([]byte, 0, (Xi * Rho * base.FieldBytes))
	for j := 0; j < Xi; j++ {
		for i := 0; i < L; i++ {
			// step 3.2: ḋ_{j,i} = γ_{j,i} + β_j * ã_{j,i}   ∀i∈[𝓁] ∀j∈[ξ]
			ddot_j[i] = scalarField.Select(bob.Beta[j] != 0, bob.Gamma[j][i], bob.Gamma[j][i].Add(r2out.ATilde[j][i]))
			// step 3.3: d_i = ∑_{j∈[ξ]} g_j * ḋ_{j,i} ∀i∈[𝓁]
			D[i] = D[i].Add(bob.gadget[j].Mul(ddot_j[i]))
		}
		for k := 0; k < Rho; k++ {
			// step 3.4: ḓ_{j,k} = γ_{j,𝓁+k} + β_j * ã_{j,l+k}   ∀k∈[ρ] ∀j∈[ξ]
			dhat_j_k = scalarField.Select(bob.Beta[j] != 0, bob.Gamma[j][L+k], bob.Gamma[j][L+k].Add(r2out.ATilde[j][L+k]))
			// step 3.5: μb'_{j,k} = ḓ_{j,k} + ∑_{i∈[𝓁]} θ_{i*ρ + k} * ḋ_{j,i} - β_j * η_k  ∀k∈[ρ] ∀j∈[ξ]
			muBoldPrime_j_k = scalarField.Select(bob.Beta[j] != 0, dhat_j_k, dhat_j_k.Sub(r2out.Eta[k]))
			for i := 0; i < L; i++ {
				muBoldPrime_j_k = muBoldPrime_j_k.Add(theta[i*Rho+k].Mul(ddot_j[i]))
			}
			muPrimeBytes = append(muPrimeBytes, muBoldPrime_j_k.Bytes()...)
		}
	}

	// step 3.6: μ' = H_{ℤ2^{2*λ_c}} (sessionId || μb')
	muPrime, err := hashing.Hash(base.RandomOracleHashFunction, bob.SessionId, muPrimeBytes)
	if err != nil {
		return nil, errs.WrapHashing(err, "bob could not hash to muPrime")
	}

	// step 3.7: Check if μ' == μ, ABORT if not
	if len(muPrime) != len(r2out.Mu) {
		return nil, errs.NewLength("len(muPrime) != len(mu)  (%d != %d)", len(muPrime), len(r2out.Mu))
	}
	if subtle.ConstantTimeCompare(muPrime, r2out.Mu) != 1 {
		return nil, errs.NewVerification("bob verification failed. muPrime != mu")
	}

	bob.Round++
	return D, nil
}
