package elgamalcommitments

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

func NewVerifier(sessionId []byte, publicKey curves.Point) (*verifier, error) { //nolint:revive // will be used by interface
	if publicKey == nil {
		return nil, errs.NewIsNil("publicKey is nil")
	}

	hBlindBytes, err := hashing.HashPrefixedLength(base.RandomOracleHashFunction, sessionId, nothingUpMySleeve)
	if err != nil {
		return nil, errs.WrapHashing(err, "failed to hash sessionId")
	}

	curve := publicKey.Curve()
	hBlind, err := curve.Hash(hBlindBytes)
	if err != nil {
		return nil, errs.WrapHashing(err, "failed to hash to curve for H")
	}

	h := publicKey.Add(hBlind)
	v := &verifier{
		h:                 h,
		homomorphicScheme: scheme,
	}

	return v, nil
}

func (v *verifier) Verify(commitment *Commitment, opening *Opening) error {
	if err := commitment.Validate(); err != nil {
		return errs.NewArgument("invalid commitment")
	}
	if err := opening.Validate(); err != nil {
		return errs.NewArgument("invalid opening")
	}

	c1, c2, err := encrypt(v.h, opening.Message, opening.Witness)
	if err != nil {
		return errs.NewFailed("could not run ElGamal encryption")
	}

	if !commitment.C1.Equal(c1) {
		return errs.NewVerification("verification failed for c1")
	}
	if !commitment.C2.Equal(c2) {
		return errs.NewVerification("verification failed for c2")
	}

	return nil
}
