package trusted_dealer

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/threshold/dkg"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/shamir"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures"
)

func Deal(protocol types.ThresholdProtocol, secret curves.Scalar, prng io.Reader) (sks datastructures.Map[types.IdentityKey, *tsignatures.SigningKeyShare], ppk datastructures.Map[types.IdentityKey, *tsignatures.PartialPublicKeys], err error) {
	if secret == nil || prng == nil {
		return nil, nil, errs.NewValidation("secret or prng is nil")
	}
	if err := types.ValidateThresholdProtocolConfig(protocol); err != nil {
		return nil, nil, errs.WrapValidation(err, "could not validate protocol config")
	}
	if protocol.Curve().Name() != secret.ScalarField().Curve().Name() {
		return nil, nil, errs.NewValidation("curve mismatch %s != %s", protocol.Curve().Name(), secret.ScalarField().Curve().Name())
	}

	shamirDealer, err := shamir.NewDealer(protocol.Threshold(), protocol.TotalParties(), protocol.Curve())
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot create Shamir dealer")
	}

	shamirShares, poly, err := shamirDealer.GeneratePolynomialAndShares(secret, prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot deal shares")
	}

	coeffsSum := make([]curves.Scalar, len(poly.Coefficients))
	for i := range coeffsSum {
		coeffsSum[i] = protocol.Curve().ScalarField().Zero()
	}

	coeffs := make([][]curves.Scalar, protocol.TotalParties())
	for i := uint(0); i < protocol.TotalParties()-1; i++ {
		coeffs[i] = make([]curves.Scalar, protocol.Threshold())
		for j := uint(0); j < protocol.Threshold(); j++ {
			coeffs[i][j], err = protocol.Curve().ScalarField().Random(prng)
			if err != nil {
				return nil, nil, errs.WrapRandomSample(err, "cannot sample scalar")
			}
			coeffsSum[j] = coeffsSum[j].Add(coeffs[i][j])
		}
	}
	coeffs[protocol.TotalParties()-1] = make([]curves.Scalar, protocol.Threshold())
	for j := uint(0); j < protocol.Threshold(); j++ {
		coeffs[protocol.TotalParties()-1][j] = poly.Coefficients[j].Sub(coeffsSum[j])
	}

	publicKey := protocol.Curve().ScalarBaseMult(secret)
	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	signingKeyShares := hashmap.NewHashableHashMap[types.IdentityKey, *tsignatures.SigningKeyShare]()
	partialPublicKeys := hashmap.NewHashableHashMap[types.IdentityKey, *tsignatures.PartialPublicKeys]()
	partialPublicKeysShares := hashmap.NewHashableHashMap[types.IdentityKey, curves.Point]()

	for sharingId, identity := range sharingConfig.Iter() {
		share := &tsignatures.SigningKeyShare{
			Share:     nil,
			PublicKey: publicKey,
		}
		for _, shamirShare := range shamirShares {
			if shamirShare.Id == uint(sharingId) {
				share.Share = shamirShare.Value
				break
			}
		}
		if share.Share == nil {
			return nil, nil, errs.NewFailed("invalid sharing id")
		}

		signingKeyShares.Put(identity, share)
		partialPublicKeysShares.Put(identity, protocol.Curve().ScalarBaseMult(share.Share))
	}

	for sharingId, identity := range sharingConfig.Iter() {
		polyCoeffs := coeffs[sharingId-1]
		commitments := make([]curves.Point, len(polyCoeffs))
		for j := range commitments {
			commitments[j] = protocol.Curve().ScalarBaseMult(polyCoeffs[j])
		}
		partialPublicKeys.Put(identity, &tsignatures.PartialPublicKeys{
			PublicKey:               publicKey,
			Shares:                  dkg.AsSharingIDMappedToPartialPublicKeys(partialPublicKeysShares),
			FeldmanCommitmentVector: commitments,
		})
	}

	return signingKeyShares, partialPublicKeys, nil
}
