package interactive_signing

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	schnorr "github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr/vanilla"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/frost"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/frost/interactive_signing/aggregation"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/frost/interactive_signing/helpers"
)

func (ic *Cosigner) Round1() (r1b *Round1Broadcast, err error) {
	// Validation
	if ic.Round != 1 {
		return nil, errs.NewRound("Running round %d but cosigner expected round %d", 1, ic.Round)
	}

	ic.state.d_i, err = ic.Curve().ScalarField().Random(ic.Prng())
	if err != nil {
		return nil, errs.WrapRandomSample(err, "could not generate random d_i")
	}
	ic.state.e_i, err = ic.Curve().ScalarField().Random(ic.Prng())
	if err != nil {
		return nil, errs.WrapRandomSample(err, "could not generate random e_i")
	}
	ic.state.D_i = ic.Curve().ScalarBaseMult(ic.state.d_i)
	ic.state.E_i = ic.Curve().ScalarBaseMult(ic.state.e_i)

	ic.Round++
	return &Round1Broadcast{
		Di: ic.state.D_i,
		Ei: ic.state.E_i,
	}, nil
}

func (ic *Cosigner) Round2(round1output network.RoundMessages[*Round1Broadcast], message []byte) (*frost.PartialSignature, error) {
	// Validation
	if ic.Round != 2 {
		return nil, errs.NewRound("Running round %d but cosigner expected round %d", 2, ic.Round)
	}
	if err := network.ValidateMessages(ic.quorum, ic.IdentityKey(), round1output); err != nil {
		return nil, errs.WrapFailed(err, "invalid round %d input", ic.Round)
	}
	if len(message) == 0 {
		return nil, errs.NewIsNil("message is empty")
	}

	D_alpha, E_alpha, err := ic.processNonceCommitmentOnline(round1output)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't not derive D alpha and E alpha")
	}
	partialSignature, err := helpers.ProducePartialSignature(
		ic,
		ic.Protocol(),
		ic.quorum,
		ic.shard.SigningKeyShare,
		ic.state.d_i, ic.state.e_i,
		D_alpha, E_alpha,
		ic.sharingConfig,
		message,
	)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not produce partial signature")
	}
	if ic.IsSignatureAggregator() {
		ic.state.aggregation.D_alpha = D_alpha
		ic.state.aggregation.E_alpha = E_alpha
	}

	ic.Round++
	return partialSignature, nil
}

func (ic *Cosigner) Aggregate(message []byte, partialSignatures network.RoundMessages[*frost.PartialSignature]) (*schnorr.Signature, error) {
	// Validation
	if ic.Round != 3 {
		return nil, errs.NewRound("Running round %d but cosigner expected round %d", 3, ic.Round)
	}
	if err := network.ValidateMessages(ic.quorum, ic.IdentityKey(), partialSignatures); err != nil {
		return nil, errs.WrapFailed(err, "invalid partial signatures")
	}
	if len(message) == 0 {
		return nil, errs.NewIsNil("message is empty")
	}

	aggregator, err := aggregation.NewSignatureAggregator(ic.myAuthKey, ic.Protocol(), ic.shard.SigningKeyShare.PublicKey, ic.shard.PublicKeyShares, ic.quorum, message, ic.state.aggregation)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not initialise signature aggregator")
	}
	signature, err := aggregator.Aggregate(partialSignatures)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not aggregate partial signatures")
	}

	ic.Terminate()
	return signature, nil
}

func (ic *Cosigner) processNonceCommitmentOnline(round1output network.RoundMessages[*Round1Broadcast]) (D_alpha, E_alpha ds.Map[types.IdentityKey, curves.Point], err error) {
	round1output.Put(ic.IdentityKey(), &Round1Broadcast{
		Di: ic.state.D_i,
		Ei: ic.state.E_i,
	})
	D_alpha = hashmap.NewHashableHashMap[types.IdentityKey, curves.Point]()
	E_alpha = hashmap.NewHashableHashMap[types.IdentityKey, curves.Point]()

	for senderIdentityKey := range ic.quorum.Iter() {
		sharingId, exists := ic.sharingConfig.Reverse().Get(senderIdentityKey)
		if !exists {
			return nil, nil, errs.NewMissing("could not find sender sharing id")
		}
		receivedMessage, exists := round1output.Get(senderIdentityKey)
		if !exists {
			return nil, nil, errs.NewMissing("do not have a message from sharing id %d", sharingId)
		}
		D_i := receivedMessage.Di
		if D_i.IsIdentity() {
			return nil, nil, errs.NewMissing("D_i of sharing id %d is at infinity", sharingId)
		}
		E_i := receivedMessage.Ei
		if E_i.IsIdentity() {
			return nil, nil, errs.NewIsIdentity("E_i of sharing id %d is at infinity", sharingId)
		}

		D_alpha.Put(senderIdentityKey, D_i)
		E_alpha.Put(senderIdentityKey, E_i)
	}
	return D_alpha, E_alpha, nil
}
