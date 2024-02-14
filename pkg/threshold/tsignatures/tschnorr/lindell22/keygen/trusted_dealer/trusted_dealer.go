package trusted_dealer

import (
	"io"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22"
)

func Keygen(protocol types.ThresholdProtocol, prng io.Reader) (ds.HashMap[types.IdentityKey, *lindell22.Shard], error) {
	if err := types.ValidateThresholdProtocolConfig(protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not validate cohort config")
	}
	if prng == nil {
		return nil, errs.NewIsNil("prng is nil")
	}

	schnorrPrivateKey, err := protocol.Curve().ScalarField().Random(prng)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "could not generate random schnorr private key")
	}
	schnorrPublicKey := protocol.Curve().ScalarBaseMult(schnorrPrivateKey)

	dealer, err := shamir.NewDealer(protocol.Threshold(), protocol.TotalParties(), protocol.Curve())
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct feldman dealer")
	}

	shamirShares, err := dealer.Split(schnorrPrivateKey, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to deal the secret")
	}

	sharingConfig := types.DeriveSharingConfig(protocol.Participants())

	publicKeySharesMap := hashmap.NewHashableHashMap[types.IdentityKey, curves.Point]()
	for pair := range sharingConfig.Iter() {
		sharingId := pair.Left
		identityKey := pair.Right
		publicKeySharesMap.Put(identityKey, protocol.Curve().ScalarBaseMult(shamirShares[sharingId-1].Value))
	}

	shards := hashmap.NewHashableHashMap[types.IdentityKey, *lindell22.Shard]()
	// TODO: fix this
	feldmanCommitmentVector := make([]curves.Point, protocol.Threshold())
	for i := range feldmanCommitmentVector {
		feldmanCommitmentVector[i] = protocol.Curve().Generator()
	}
	for pair := range sharingConfig.Iter() {
		sharingId := pair.Left
		identityKey := pair.Right
		share := shamirShares[int(sharingId)-1].Value
		shards.Put(identityKey, &lindell22.Shard{
			SigningKeyShare: &tsignatures.SigningKeyShare{
				Share:     share,
				PublicKey: schnorrPublicKey,
			},
			PublicKeyShares: &tsignatures.PartialPublicKeys{
				PublicKey:               schnorrPublicKey,
				Shares:                  publicKeySharesMap,
				FeldmanCommitmentVector: feldmanCommitmentVector,
			},
		})
	}

	return shards, nil
}
