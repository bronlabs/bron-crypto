package interactive

import (
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/signatures/eddsa"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/frost"
	signing_helpers "github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/frost/signing"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/frost/signing/aggregation"
)

type Round1Broadcast struct {
	Di curves.Point
	Ei curves.Point
}

func (ic *Cosigner) Round1() (*Round1Broadcast, error) {
	if ic.round != 1 {
		return nil, errs.NewInvalidRound("round mismatch %d != 1", ic.round)
	}
	ic.state.d_i = ic.CohortConfig.CipherSuite.Curve.Scalar().Random(ic.prng)
	ic.state.e_i = ic.CohortConfig.CipherSuite.Curve.Scalar().Random(ic.prng)
	ic.state.D_i = ic.CohortConfig.CipherSuite.Curve.ScalarBaseMult(ic.state.d_i)
	ic.state.E_i = ic.CohortConfig.CipherSuite.Curve.ScalarBaseMult(ic.state.e_i)
	ic.round++
	return &Round1Broadcast{
		Di: ic.state.D_i,
		Ei: ic.state.E_i,
	}, nil
}

func (ic *Cosigner) Round2(round1output map[integration.IdentityKey]*Round1Broadcast, message []byte) (*frost.PartialSignature, error) {
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
	partialSignature, err := signing_helpers.ProducePartialSignature(
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

func (ic *Cosigner) Aggregate(message []byte, partialSignatures map[integration.IdentityKey]*frost.PartialSignature) (*eddsa.Signature, error) {
	if ic.round != 3 {
		return nil, errs.NewInvalidRound("round mismatch %d != 3", ic.round)
	}
	aggregator, err := aggregation.NewSignatureAggregator(ic.MyIdentityKey, ic.CohortConfig, ic.Shard, ic.SessionParticipants, ic.IdentityKeyToSharingId, message, ic.state.aggregation)
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

func (ic *Cosigner) processNonceCommitmentOnline(round1output map[integration.IdentityKey]*Round1Broadcast) (D_alpha, E_alpha map[integration.IdentityKey]curves.Point, err error) {
	round1output[ic.MyIdentityKey] = &Round1Broadcast{
		Di: ic.state.D_i,
		Ei: ic.state.E_i,
	}

	D_alpha = map[integration.IdentityKey]curves.Point{}
	E_alpha = map[integration.IdentityKey]curves.Point{}

	for _, senderIdentityKey := range ic.SessionParticipants {
		sharingId, exists := ic.IdentityKeyToSharingId[senderIdentityKey]
		if !exists {
			return nil, nil, errs.NewMissing("sender identity key is not found")
		}
		receivedMessage, exists := round1output[senderIdentityKey]
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
			return nil, nil, errs.NewNotOnCurve("E_i of sharing id %d is not on curve", sharingId)
		}

		D_alpha[senderIdentityKey] = D_i
		E_alpha[senderIdentityKey] = E_i
	}
	return D_alpha, E_alpha, nil
}
