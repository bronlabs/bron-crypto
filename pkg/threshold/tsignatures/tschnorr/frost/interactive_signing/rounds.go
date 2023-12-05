package interactive_signing

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	schnorr "github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr/vanilla"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/frost"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/frost/interactive_signing/aggregation"
)

type Round1Broadcast struct {
	Di curves.Point
	Ei curves.Point

	_ types.Incomparable
}

func (ic *Cosigner) Round1() (r1b *Round1Broadcast, err error) {
	if ic.round != 1 {
		return nil, errs.NewInvalidRound("round mismatch %d != 1", ic.round)
	}
	ic.state.d_i, err = ic.CohortConfig.CipherSuite.Curve.Scalar().Random(ic.prng)
	if err != nil {
		return nil, errs.WrapRandomSampleFailed(err, "could not generate random d_i")
	}
	ic.state.e_i, err = ic.CohortConfig.CipherSuite.Curve.Scalar().Random(ic.prng)
	if err != nil {
		return nil, errs.WrapRandomSampleFailed(err, "could not generate random e_i")
	}
	ic.state.D_i = ic.CohortConfig.CipherSuite.Curve.ScalarBaseMult(ic.state.d_i)
	ic.state.E_i = ic.CohortConfig.CipherSuite.Curve.ScalarBaseMult(ic.state.e_i)
	ic.round++
	return &Round1Broadcast{
		Di: ic.state.D_i,
		Ei: ic.state.E_i,
	}, nil
}

func (ic *Cosigner) Round2(round1output map[types.IdentityHash]*Round1Broadcast, message []byte) (*frost.PartialSignature, error) {
	if ic.round != 2 {
		return nil, errs.NewInvalidRound("round mismatch %d != 2", ic.round)
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
	partialSignature, err := ProducePartialSignature(
		ic,
		ic.SessionParticipants,
		ic.Shard.SigningKeyShare,
		ic.state.d_i, ic.state.e_i,
		D_alpha, E_alpha,
		ic.SharingIdToIdentityKey,
		ic.IdentityKeyToSharingId,
		ic.state.aggregation,
		message,
	)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not produce partial signature")
	}
	ic.state.d_i = nil
	ic.state.e_i = nil
	ic.round++
	return partialSignature, nil
}

func (ic *Cosigner) Aggregate(message []byte, partialSignatures map[types.IdentityHash]*frost.PartialSignature) (*schnorr.Signature, error) {
	if ic.round != 3 {
		return nil, errs.NewInvalidRound("round mismatch %d != 3", ic.round)
	}
	aggregator, err := aggregation.NewSignatureAggregator(ic.MyAuthKey, ic.CohortConfig, ic.Shard, ic.SessionParticipants, ic.IdentityKeyToSharingId, message, ic.state.aggregation)
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

func (ic *Cosigner) processNonceCommitmentOnline(round1output map[types.IdentityHash]*Round1Broadcast) (D_alpha, E_alpha map[types.IdentityHash]curves.Point, err error) {
	round1output[ic.MyAuthKey.Hash()] = &Round1Broadcast{
		Di: ic.state.D_i,
		Ei: ic.state.E_i,
	}

	D_alpha = map[types.IdentityHash]curves.Point{}
	E_alpha = map[types.IdentityHash]curves.Point{}

	for _, senderIdentityKey := range ic.SessionParticipants.Iter() {
		sharingId, exists := ic.IdentityKeyToSharingId[senderIdentityKey.Hash()]
		if !exists {
			return nil, nil, errs.NewMissing("sender identity key is not found")
		}
		receivedMessage, exists := round1output[senderIdentityKey.Hash()]
		if !exists {
			return nil, nil, errs.NewMissing("do not have a message from sharing id %d", sharingId)
		}
		D_i := receivedMessage.Di
		if D_i.IsIdentity() {
			return nil, nil, errs.NewMissing("D_i of sharing id %d is at infinity", sharingId)
		}
		if !D_i.IsOnCurve() {
			return nil, nil, errs.NewMissing("D_i of sharing id %d is not on curve", sharingId)
		}
		E_i := receivedMessage.Ei
		if E_i.IsIdentity() {
			return nil, nil, errs.NewIsIdentity("E_i of sharing id %d is at infinity", sharingId)
		}
		if !E_i.IsOnCurve() {
			return nil, nil, errs.NewMembership("E_i of sharing id %d is not on curve", sharingId)
		}

		D_alpha[senderIdentityKey.Hash()] = D_i
		E_alpha[senderIdentityKey.Hash()] = E_i
	}
	return D_alpha, E_alpha, nil
}
