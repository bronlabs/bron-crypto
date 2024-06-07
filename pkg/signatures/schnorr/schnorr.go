package schnorr

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
)

func MakeGenericSchnorrChallenge(suite types.SigningSuite, xs ...[]byte) (curves.Scalar, error) {
	for _, x := range xs {
		if x == nil {
			return nil, errs.NewIsNil("an input is nil")
		}
	}

	digest, err := hashing.Hash(suite.Hash(), xs...)
	if err != nil {
		return nil, errs.WrapHashing(err, "could not compute fiat shamir hash")
	}

	var challenge curves.Scalar
	// In EdDSA and relevant chains like NEM, the digest is treated and passed as little endian, however for consistency, all our curves' inputs are big endian.
	if suite.Curve().Name() == edwards25519.Name {
		challenge, err = edwards25519.NewScalar(0).SetBytesWideLE(digest)
	} else {
		challenge, err = suite.Curve().ScalarField().Element().SetBytesWide(digest)
	}
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not compute fiat shamir challenge")
	}
	return challenge, nil
}
