package trusted_dealer

import (
	"github.com/bronlabs/krypton-primitives/pkg/base/polynomials"
	feldman_vss "github.com/bronlabs/krypton-primitives/pkg/threshold/sharing/feldman"
	"io"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	"github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	"github.com/bronlabs/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/tsignatures"
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

	feldmanDealer, err := feldman_vss.NewScheme(protocol.Threshold(), protocol.TotalParties(), protocol.Curve())
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot create Feldman-VSS dealer")
	}
	shares, verification, err := feldmanDealer.DealVerifiable(secret, prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot deal shares")
	}

	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	publicShares := hashmap.NewComparableHashMap[types.SharingID, curves.Point]()
	for sharingId := range sharingConfig.Iter() {
		publicShares.Put(sharingId, polynomials.EvalInExponent(verification, sharingId.ToScalar(protocol.Curve().ScalarField())))
	}

	sks = hashmap.NewHashableHashMap[types.IdentityKey, *tsignatures.SigningKeyShare]()
	for sharingId, identityKey := range sharingConfig.Iter() {
		sks.Put(identityKey, &tsignatures.SigningKeyShare{
			Share:     shares[sharingId].Value,
			PublicKey: verification[0],
		})
	}

	ppk = hashmap.NewHashableHashMap[types.IdentityKey, *tsignatures.PartialPublicKeys]()
	for _, identityKey := range sharingConfig.Iter() {
		ppk.Put(identityKey, &tsignatures.PartialPublicKeys{
			PublicKey:               verification[0],
			Shares:                  publicShares,
			FeldmanCommitmentVector: verification,
		})
	}

	return sks, ppk, nil
}
