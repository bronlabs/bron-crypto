package tsignatures

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
)

func ConstructPrivateKey(protocol types.ThresholdSignatureProtocol, shards ds.Map[types.IdentityKey, Shard]) (curves.Scalar, error) {
	if err := validatePrivateKeyConstructionInputs(protocol, shards); err != nil {
		return nil, errs.WrapArgument(err, "couldn't construct private key")
	}
	shamirDealer, err := shamir.NewDealer(protocol.Threshold(), protocol.TotalParties(), protocol.Curve())
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create shamir dealer")
	}
	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	shares := make([]*shamir.Share, shards.Size())
	var publicKey curves.Point
	index := 0
	for pair := range shards.Iter() {
		identityKey := pair.Key
		shard := pair.Value
		sharingId, exists := sharingConfig.Reverse().Get(identityKey)
		if !exists {
			return nil, errs.NewMissing("couldn't find sharing id for identity key %s", identityKey.String())
		}
		shares[index] = &shamir.Share{
			Id:    uint(sharingId),
			Value: shard.SecretShare(),
		}
		index++
		if publicKey == nil {
			publicKey = shard.PublicKey()
		}
	}
	recoveredPrivateKey, err := shamirDealer.Combine(shares...)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to combine shares")
	}
	recoveredPublicKey := protocol.Curve().ScalarBaseMult(recoveredPrivateKey)
	if !recoveredPublicKey.Equal(publicKey) {
		return nil, errs.NewVerification("constructed private key is incorrect")
	}
	return recoveredPrivateKey, nil
}

func validatePrivateKeyConstructionInputs(protocol types.ThresholdSignatureProtocol, shards ds.Map[types.IdentityKey, Shard]) error {
	if err := types.ValidateThresholdSignatureProtocolConfig(protocol); err != nil {
		return errs.WrapValidation(err, "protocol config")
	}
	if shards == nil {
		return errs.NewIsNil("keyShares")
	}
	shardHolders := hashset.NewHashableHashSet(shards.Keys()...)
	if !shardHolders.IsSubSet(protocol.Participants()) {
		return errs.NewMembership("shardholder set is not a subset of total participants")
	}
	if shardHolders.Size() < int(protocol.Threshold()) {
		return errs.NewSize("shard holder set size (%d) < threshold (%d)", shardHolders.Size(), protocol.Threshold())
	}
	var seenPublicKey curves.Point
	for holder := range shardHolders.Iter() {
		shard, exists := shards.Get(holder)
		if !exists {
			return errs.NewMissing("couldn't find shard for holder %s", holder.String())
		}
		sks := &SigningKeyShare{
			Share:     shard.SecretShare(),
			PublicKey: shard.PublicKey(),
		}
		if err := sks.Validate(protocol); err != nil {
			return errs.WrapValidation(err, "signing key shares")
		}
		ppk := &PartialPublicKeys{
			PublicKey:               shard.PublicKey(),
			Shares:                  shard.PartialPublicKeys(),
			FeldmanCommitmentVector: shard.FeldmanCommitmentVector(),
		}
		if err := ppk.Validate(protocol); err != nil {
			return errs.WrapValidation(err, "partial public keys")
		}

		if seenPublicKey == nil {
			seenPublicKey = shard.PublicKey()
		} else if !seenPublicKey.Equal(shard.PublicKey()) {
			return errs.NewValue("not all public keys are the same")
		}
	}
	return nil
}
