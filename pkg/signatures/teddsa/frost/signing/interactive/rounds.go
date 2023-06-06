package interactive

import (
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost"
	signing_helpers "github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost/signing"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost/signing/aggregation"
	"github.com/pkg/errors"
)

type Round1Broadcast struct {
	Di curves.Point
	Ei curves.Point
}

func (ic *InteractiveCosigner) Round1() (*Round1Broadcast, error) {
	if ic.round != 1 {
		return nil, errors.Errorf("%s round mismatch %d != 1", errs.InvalidRound, ic.round)
	}
	ic.state.d_i = ic.CohortConfig.CipherSuite.Curve.Scalar.Random(ic.prng)
	ic.state.e_i = ic.CohortConfig.CipherSuite.Curve.Scalar.Random(ic.prng)
	ic.state.D_i = ic.CohortConfig.CipherSuite.Curve.ScalarBaseMult(ic.state.d_i)
	ic.state.E_i = ic.CohortConfig.CipherSuite.Curve.ScalarBaseMult(ic.state.e_i)
	ic.round++
	return &Round1Broadcast{
		Di: ic.state.D_i,
		Ei: ic.state.E_i,
	}, nil
}

func (ic *InteractiveCosigner) Round2(round1output map[integration.IdentityKey]*Round1Broadcast, message []byte) (*frost.PartialSignature, error) {
	if ic.round != 2 {
		return nil, errors.Errorf("%s round mismatch %d != 2", errs.InvalidRound, ic.round)
	}
	D_alpha, E_alpha, err := ic.processNonceCommitmentOnline(round1output)
	if err != nil {
		return nil, errors.Wrapf(err, "%s couldn't not derive D alpha and E alpha", errs.Failed)
	}
	partialSignature, err := signing_helpers.ProducePartialSignature(
		ic,
		ic.SessionParticipants,
		ic.SigningKeyShare,
		ic.state.d_i, ic.state.e_i,
		D_alpha, E_alpha,
		ic.ShamirIdToIdentityKey,
		ic.IdentityKeyToShamirId,
		ic.state.aggregation,
		message,
	)
	if err != nil {
		return nil, errors.Wrapf(err, "%s could not produce partial signature", errs.Failed)
	}
	ic.state.d_i = nil
	ic.state.e_i = nil
	ic.round++
	return partialSignature, nil
}

func (ic *InteractiveCosigner) Aggregate(message []byte, partialSignatures map[integration.IdentityKey]*frost.PartialSignature) (*frost.Signature, error) {
	if ic.round != 3 {
		return nil, errors.Errorf("%s round mismatch %d != 3", errs.InvalidRound, ic.round)
	}
	aggregator, err := aggregation.NewSignatureAggregator(ic.MyIdentityKey, ic.CohortConfig, ic.SigningKeyShare.PublicKey, ic.PublicKeyShares, ic.SessionParticipants, ic.IdentityKeyToShamirId, message, ic.state.aggregation)
	if err != nil {
		return nil, errors.Wrapf(err, "%s could not initialize signature aggregator", errs.Failed)
	}
	signature, err := aggregator.Aggregate(partialSignatures)
	if err != nil {
		return nil, errors.Wrapf(err, "%s could not aggregate partial signatures", errs.Failed)
	}
	ic.round++
	return signature, err
}

func (ic *InteractiveCosigner) processNonceCommitmentOnline(round1output map[integration.IdentityKey]*Round1Broadcast) (D_alpha, E_alpha map[integration.IdentityKey]curves.Point, err error) {
	round1output[ic.MyIdentityKey] = &Round1Broadcast{
		Di: ic.state.D_i,
		Ei: ic.state.E_i,
	}

	D_alpha = map[integration.IdentityKey]curves.Point{}
	E_alpha = map[integration.IdentityKey]curves.Point{}

	for _, senderIdentityKey := range ic.SessionParticipants {
		shamirId, exists := ic.IdentityKeyToShamirId[senderIdentityKey]
		if !exists {
			return nil, nil, errors.Errorf("%s sender identity key is not found", errs.Missing)
		}
		receivedMessage, exists := round1output[senderIdentityKey]
		if !exists {
			return nil, nil, errors.Errorf("%s do not have a message from shamir id %d", errs.Missing, shamirId)
		}
		D_i := receivedMessage.Di
		if D_i.IsIdentity() {
			return nil, nil, errors.Errorf("%s D_i of shamir id %d is at infinity", errs.Missing, shamirId)
		}
		if !D_i.IsOnCurve() {
			return nil, nil, errors.Errorf("%s D_i of shamir id %d is not on curve", errs.Missing, shamirId)
		}
		E_i := receivedMessage.Ei
		if E_i.IsIdentity() {
			return nil, nil, errors.Errorf("%s E_i of shamir id %d is at infinity", errs.IsIdentity, shamirId)
		}
		if !E_i.IsOnCurve() {
			return nil, nil, errors.Errorf("%s E_i of shamir id %d is not on curve", errs.NotOnCurve, shamirId)
		}

		D_alpha[senderIdentityKey] = D_i
		E_alpha[senderIdentityKey] = E_i
	}
	return D_alpha, E_alpha, nil
}
