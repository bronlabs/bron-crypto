package dkls23

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

// TODO: make it whatever it needs to be
type PartialSignature[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	r P
	u S
	w S
}

func NewPartialSignature[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]](r P, u, w S) *PartialSignature[P, B, S] {
	// TODO: add validations
	return &PartialSignature[P, B, S]{
		r,
		u,
		w,
	}
}

// Aggregate computes the sum of partial signatures to get a valid signature. It also normalises the signature to the low-s form as well as attaches the recovery id to the final signature.
func Aggregate[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]](suite ecdsa.Suite[P, B, S], publicKey P, partialSignatures ...*PartialSignature[P, B, S]) (*ecdsa.Signature[S], error) {
	w := suite.ScalarField().Zero()
	u := suite.ScalarField().Zero()
	R := suite.Curve().OpIdentity()

	// step 4.1: R <- Σ R_i   &    rx <- R_x
	for _, partialSignature := range partialSignatures {
		w = w.Add(partialSignature.w)
		u = u.Add(partialSignature.u)
		R = R.Add(partialSignature.r)
	}

	// step 4.2: s <- (Σ w_i) / (Σ u_i)
	uInv, err := u.TryInv()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot compute w/u")
	}
	s := w.Mul(uInv)

	rx, err := suite.ScalarField().FromWideBytes(R.Coordinates().Value()[0].Bytes()) // TODO: fingers crossed it returns affine x
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot convert to scalar")
	}

	// TODO: Add recovery id
	//// step 4.3: v <- (R_y mod 2) + 2(R_x > q)
	//v, err := ecdsa.CalculateRecoveryId(R)
	//if err != nil {
	//	return nil, errs.WrapFailed(err, "could not compute recovery id")
	//}

	// steps 4.4-4.6: s = min(s, -s mod q);    v = v + 2 · (s > -s mod q)
	sigma := ecdsa.NewSignature(rx, s, nil)
	sigma.Normalise()

	// step 4.7
	//if err := ecdsa.Verify(sigma, cipherSuite.Hash(), publicKey, message); err != nil {
	//	return nil, errs.WrapVerification(err, "sigma is invalid")
	//}
	return sigma, nil
}
