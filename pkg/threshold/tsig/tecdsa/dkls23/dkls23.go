package dkls23

import (
	crand "crypto/rand"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

type PartialSignature[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	r P
	u S
	w S
}

func NewPartialSignature[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](r P, u, w S) (*PartialSignature[P, B, S], error) {
	if r.IsOpIdentity() || u.IsZero() {
		return nil, errs.NewFailed("invalid arguments")
	}

	ps := &PartialSignature[P, B, S]{
		r,
		u,
		w,
	}
	return ps, nil
}

// Aggregate computes the sum of partial signatures to get a valid signature. It also normalises the signature to the low-s form as well as attaches the recovery id to the final signature.
func Aggregate[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](suite *ecdsa.Suite[P, B, S], publicKey *ecdsa.PublicKey[P, B, S], message []byte, partialSignatures ...*PartialSignature[P, B, S]) (*ecdsa.Signature[S], error) {
	w := suite.ScalarField().Zero()
	u := suite.ScalarField().Zero()
	r := suite.Curve().OpIdentity()

	r = partialSignatures[0].r
	for i, partialSignature := range partialSignatures {
		w = w.Add(partialSignature.w)
		u = u.Add(partialSignature.u)

		if !partialSignature.r.Equal(r) {
			return nil, errs.NewFailed("partial signature mismatch between indices 0 and %d", i)
		}
	}

	uInv, err := u.TryInv()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot compute w/u")
	}
	s := w.Mul(uInv)

	rxi, err := r.AffineX()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot compute affine x")
	}
	rx, err := suite.ScalarField().FromWideBytes(rxi.Bytes())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot convert to scalar")
	}

	v, err := ecdsa.ComputeRecoveryId(r)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not compute recovery id")
	}

	signature, err := ecdsa.NewSignature(rx, s, &v)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create signature")
	}
	signature.Normalise()

	scheme, err := ecdsa.NewScheme(suite, crand.Reader)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create scheme")
	}
	verifier, err := scheme.Verifier()
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create verifier")
	}
	if err := verifier.Verify(signature, publicKey, message); err != nil {
		return nil, errs.WrapVerification(err, "signature is invalid")
	}

	return signature, nil
}
