package mult

import (
	"crypto/subtle"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/ct"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	"github.com/copperexchange/krypton-primitives/pkg/ot"
	"github.com/copperexchange/krypton-primitives/pkg/ot/extension/softspoken"
)

type Round1Output = softspoken.Round1Output

func (bob *Bob) Round1() (b curves.Scalar, r1out *Round1Output, err error) {
	// step 1.1: Sample β ∈ [ξ]bits
	bob.Beta = make(ot.ChoiceBits, XiBytes)
	if _, err := bob.csrand.Read(bob.Beta); err != nil {
		return nil, nil, errs.WrapRandomSample(err, "bob could not sample beta")
	}

	// step 1.2: Run OTE.Round1(β) ---> γ ∈ ℤq^[ξ]
	OTeReceiverOut, r1out, err := bob.receiver.Round1(bob.Beta)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "bob step 1.3")
	}
	for j := 0; j < Xi; j++ {
		for l := 0; l < LOTe; l++ {
			bob.Gamma[j][l], err = bob.Curve.Scalar().ScalarField().Hash(OTeReceiverOut[j][l][:])
			if err != nil {
				return nil, nil, errs.WrapFailed(err, "bob could not hash to gamma")
			}
		}
	}

	bob.Beta = bitstring.UnpackBits(bob.Beta) // unpack beta for easier access to individual bits

	// step 1.3: b = ∑_{j∈[ξ]} β_j * g_j
	b = bob.Curve.Scalar().ScalarField().Zero()
	for j := 0; j < Xi; j++ {
		b = ct.SelectScalar(bob.Beta[j], b.Add(bob.gadget[j]), b)
	}

	return b, r1out, nil
}

type Round2Output struct {
	ATilde [Xi][LOTe]curves.Scalar
	Eta    [Rho]curves.Scalar
	Mu     []byte

	_ ds.Incomparable
}

func (alice *Alice) Round2(r1out *Round1Output, a RvoleAliceInput) (c *OutputShares, r2o *Round2Output, err error) {
	C := new(OutputShares)

	// step 2.1: Run OTE.Round2(...) --> (α0_j, α1_j) ∈ ℤq^[LOTe]   ∀j∈[ξ]
	alphaBits, err := alice.sender.Round2(r1out)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "alice cote round 2")
	}
	var alpha0, alpha1 [Xi][LOTe]curves.Scalar
	for j := 0; j < Xi; j++ {
		for l := 0; l < LOTe; l++ {
			alpha0[j][l], err = alice.Curve.Scalar().ScalarField().Hash(alphaBits[j][0][l][:])
			if err != nil {
				return nil, nil, errs.WrapHashing(err, "could not hash to alpha0j")
			}
			alpha1[j][l], err = alice.Curve.Scalar().ScalarField().Hash(alphaBits[j][1][l][:])
			if err != nil {
				return nil, nil, errs.WrapHashing(err, "could not hash to alpha1j")
			}
		}
	}

	// step 2.2: C_i = ∑_{j∈[ξ]} α_0_j * g_j   ∀i∈[𝓁]
	for i := 0; i < L; i++ {
		C[i] = alice.Curve.Scalar().ScalarField().Zero()
		for j := 0; j < Xi; j++ {
			C[i] = C[i].Sub(alice.gadget[j].Mul(alpha0[j][i]))
		}
	}

	// step 2.3: Sample â ∈ ℤq^[ρ]
	var aHat [Rho]curves.Scalar
	for k := 0; k < Rho; k++ {
		aHat[k], err = alice.Curve.Scalar().ScalarField().Random(alice.csrand)
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

	// step 2.5: θ <--- H_{ℤq^{𝓁xρ}} (ã || sid)
	theta, err := alice.Curve.HashToScalars(L*Rho, alice.uniqueSessionId, aTildeBytes)
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

	// step 2.8: μ = H_{ℤ2^{2*λ_c}} (sid || μb)
	mu, err := hashing.Hash(base.RandomOracleHashFunction, alice.uniqueSessionId, muBytes)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not hash to Mu")
	}

	return C, &Round2Output{ATilde: aTilde, Eta: eta, Mu: mu}, nil
}

func (bob *Bob) Round3(r2o *Round2Output) (D *[L]curves.Scalar, err error) {
	D = new([L]curves.Scalar)
	for i := 0; i < L; i++ {
		D[i] = bob.Curve.Scalar().ScalarField().Zero()
	}

	// step 3.1: θ <--- H_{ℤq^{𝓁xρ}} (ã || sid)
	aTildeBytes := make([]byte, 0, ((L + Rho) * Xi * base.FieldBytes))
	for j := 0; j < Xi; j++ {
		for i := 0; i < L; i++ {
			aTildeBytes = append(aTildeBytes, r2o.ATilde[j][i].Bytes()...)
		}
		for k := 0; k < Rho; k++ {
			aTildeBytes = append(aTildeBytes, r2o.ATilde[j][L+k].Bytes()...)
		}
	}
	theta, err := bob.Curve.HashToScalars(L*Rho, bob.uniqueSessionId, aTildeBytes)
	if err != nil {
		return nil, errs.WrapFailed(err, "bob could not hash to theta")
	}

	// step 3.2
	var ddot_j [L]curves.Scalar
	var dhat_j_k, muBoldPrime_j_k curves.Scalar
	muPrimeBytes := make([]byte, 0, (Xi * Rho * base.FieldBytes))
	for j := 0; j < Xi; j++ {
		for i := 0; i < L; i++ {
			// step 3.2.1: ḋ_{j,i} = α1_{j,i} + β_j * (α0_{j,i} - α1_{j,i} + a_i) ∀i∈[𝓁] ∀j∈[ξ]
			ddot_j[i] = ct.SelectScalar(bob.Beta[j], bob.Gamma[j][i].Add(r2o.ATilde[j][i]), bob.Gamma[j][i])
			// step 3.2.2: d_i = ∑_{j∈[ξ]} g_j * ḋ_{j,i} ∀i∈[𝓁]
			D[i] = D[i].Add(bob.gadget[j].Mul(ddot_j[i]))
		}
		for k := 0; k < Rho; k++ {
			// step 3.2.3: d'_{j, k} = α1_{j,𝓁+k} + β_j * (α0_{j,𝓁+k} - α1_{j,l+k} + â_k) ∀k∈[ρ] ∀j∈[ξ]
			dhat_j_k = ct.SelectScalar(bob.Beta[j], bob.Gamma[j][L+k].Add(r2o.ATilde[j][L+k]), bob.Gamma[j][L+k])
			// step 3.2.4: μb'_{j,k} = α0_{j,l+k} + ∑_{i∈[𝓁]} θ_{i*ρ + k} * α0_{j,i} - β_j * η_k  ∀k∈[ρ] ∀j∈[ξ]
			muBoldPrime_j_k = ct.SelectScalar(bob.Beta[j], dhat_j_k.Sub(r2o.Eta[k]), dhat_j_k)
			for i := 0; i < L; i++ {
				muBoldPrime_j_k = muBoldPrime_j_k.Add(theta[i*Rho+k].Mul(ddot_j[i]))
			}
			muPrimeBytes = append(muPrimeBytes, muBoldPrime_j_k.Bytes()...)
		}
	}

	// step 3.3: μ' = H_{ℤ2^{2*λ_c}} (sid || μb')
	muPrime, err := hashing.Hash(base.RandomOracleHashFunction, bob.uniqueSessionId, muPrimeBytes)
	if err != nil {
		return nil, errs.WrapFailed(err, "bob could not hash to muPrime")
	}

	// step 3.4: Check if μ' == μ, ABORT if not
	if len(muPrime) != len(r2o.Mu) {
		return nil, errs.NewLength("len(muPrime) != len(Mu)  (%d != %d)", len(muPrime), len(r2o.Mu))
	}
	if subtle.ConstantTimeCompare(muPrime, r2o.Mu) != 1 {
		return nil, errs.NewVerification("bob verification failed. muPrime != Mu")
	}

	return D, nil
}
