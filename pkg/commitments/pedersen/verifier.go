package pedersencommitments

import (
	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
)

var _ commitments.HomomorphicVerifier[Message, *Commitment, *Opening] = (*verifier)(nil)

type verifier struct {
	h curves.Point
	*homomorphicScheme
}

func NewVerifier(sessionId []byte, curve curves.Curve) (*verifier, error) { //nolint:revive // will be used by interface
	if curve == nil {
		return nil, errs.NewIsNil("curve is nil")
	}

	hBytes, err := hashing.HashChain(base.RandomOracleHashFunction, nothingUpMySleeve)
	if err != nil {
		return nil, errs.WrapHashing(err, "failed to hash sessionId")
	}

	h, err := curve.Hash(hBytes)
	if err != nil {
		return nil, errs.WrapHashing(err, "failed to hash to curve for H")
	}

	v := &verifier{
		h:                 h,
		homomorphicScheme: scheme,
	}
	return v, nil
}

func (v *verifier) Verify(commitment *Commitment, opening *Opening) error {
	if err := commitment.Validate(); err != nil {
		return errs.WrapFailed(err, "invalid commitment")
	}
	if err := opening.Validate(); err != nil {
		return errs.WrapFailed(err, "invalid opening")
	}

	curve := v.h.Curve()
	if curve.Name() != opening.message.ScalarField().Curve().Name() {
		return errs.NewArgument("curves do not match")
	}

	mG := curve.Generator().ScalarMul(opening.message)
	rH := v.h.ScalarMul(opening.witness)
	c := rH.Add(mG)
	if !commitment.value.Equal(c) {
		return errs.NewVerification("verification failed")
	}

	return nil
}
