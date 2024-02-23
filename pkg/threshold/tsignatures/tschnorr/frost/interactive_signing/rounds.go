package interactive_signing

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	schnorr "github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr/vanilla"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/frost"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/frost/interactive_signing/aggregation"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/frost/interactive_signing/helpers"
)

type Round1Broadcast struct {
	Di curves.Point
	Ei curves.Point

	_ ds.Incomparable
}

func (ic *Cosigner) Round1() (r1b *Round1Broadcast, err error) {
	if ic.round != 1 {
		return nil, errs.NewRound("round mismatch %d != 1", ic.round)
	}
	ic.state.d_i, err = ic.protocol.CipherSuite().Curve().ScalarField().Random(ic.prng)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "could not generate random d_i")
	}
	ic.state.e_i, err = ic.protocol.CipherSuite().Curve().ScalarField().Random(ic.prng)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "could not generate random e_i")
	}
	ic.state.D_i = ic.protocol.CipherSuite().Curve().ScalarBaseMult(ic.state.d_i)
	ic.state.E_i = ic.protocol.CipherSuite().Curve().ScalarBaseMult(ic.state.e_i)
	ic.round++
	return &Round1Broadcast{
		Di: ic.state.D_i,
		Ei: ic.state.E_i,
	}, nil
}

func (ic *Cosigner) Round2(round1output types.RoundMessages[*Round1Broadcast], message []byte) (*frost.PartialSignature, error) {
	if ic.round != 2 {
		return nil, errs.NewRound("round mismatch %d != 2", ic.round)
	}
	D_alpha, E_alpha, err := ic.processNonceCommitmentOnline(round1output)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't not derive D alpha and E alpha")
	}
	if message == nil {
		return nil, errs.NewIsNil("message is empty")
	}
	if len(message) == 0 {
		return nil, errs.NewIsZero("message is empty")
	}
	partialSignature, err := helpers.ProducePartialSignature(
		ic,
		ic.protocol,
		ic.sessionParticipants,
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
	ic.round++
	return partialSignature, nil
}

func (ic *Cosigner) Aggregate(message []byte, partialSignatures types.RoundMessages[*frost.PartialSignature]) (*schnorr.Signature, error) {
	if ic.round != 3 {
		return nil, errs.NewRound("round mismatch %d != 3", ic.round)
	}
	aggregator, err := aggregation.NewSignatureAggregator(ic.myAuthKey, ic.protocol, ic.shard.SigningKeyShare.PublicKey, ic.shard.PublicKeyShares, ic.sessionParticipants, message, ic.state.aggregation)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not initialise signature aggregator")
	}
	signature, err := aggregator.Aggregate(partialSignatures)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not aggregate partial signatures")
	}
	ic.round++
	return signature, nil
}

func (ic *Cosigner) processNonceCommitmentOnline(round1output types.RoundMessages[*Round1Broadcast]) (D_alpha, E_alpha ds.Map[types.IdentityKey, curves.Point], err error) {
	round1output.Put(ic.IdentityKey(), &Round1Broadcast{
		Di: ic.state.D_i,
		Ei: ic.state.E_i,
	})
	D_alpha = hashmap.NewHashableHashMap[types.IdentityKey, curves.Point]()
	E_alpha = hashmap.NewHashableHashMap[types.IdentityKey, curves.Point]()

	for senderIdentityKey := range ic.sessionParticipants.Iter() {
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
