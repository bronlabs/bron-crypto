package interactive

import (
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/sharing"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost/signing/aggregation"
	"github.com/copperexchange/crypto-primitives-go/pkg/zkp/schnorr"
	"github.com/pkg/errors"
)

type Round1Broadcast struct {
	Di curves.Point
	Ei curves.Point
}

func (ic *InteractiveCosigner) Round1() (*Round1Broadcast, error) {
	if ic.round != 1 {
		return nil, errors.New("round mismatch")
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
		return nil, errors.New("round mismatch")
	}
	D_alpha, E_alpha, err := ic.processNonceCommitmentOnline(round1output)
	if err != nil {
		return nil, errors.Wrap(err, "couldn't not derive D alpha and E alpha")
	}
	partialSignature, err := Helper_ProducePartialSignature(
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
		return nil, errors.Wrap(err, "could not produce partial signature")
	}
	ic.state.d_i = nil
	ic.state.e_i = nil
	ic.round++
	return partialSignature, nil
}

func (ic *InteractiveCosigner) Aggregate(message []byte, partialSignatures map[integration.IdentityKey]*frost.PartialSignature) (*frost.Signature, error) {
	if ic.round != 3 {
		return nil, errors.New("round mismatch")
	}
	aggregator, err := aggregation.NewSignatureAggregator(ic.MyIdentityKey, ic.CohortConfig, ic.SigningKeyShare.PublicKey, ic.PublicKeyShares, ic.SessionParticipants, ic.IdentityKeyToShamirId, message, ic.state.aggregation)
	if err != nil {
		return nil, errors.Wrap(err, "could not initialize signature aggregator")
	}
	signature, err := aggregator.Aggregate(partialSignatures)
	if err != nil {
		return nil, errors.Wrap(err, "could not aggregate partial signatures")
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
			return nil, nil, errors.New("sender identity key is not found")
		}
		receivedMessage, exists := round1output[senderIdentityKey]
		if !exists {
			return nil, nil, errors.Errorf("do not have a message from shamir id %d", shamirId)
		}
		D_i := receivedMessage.Di
		if D_i.IsIdentity() {
			return nil, nil, errors.Errorf("D_i of shamir id %d is at infinity", shamirId)
		}
		if !D_i.IsOnCurve() {
			return nil, nil, errors.Errorf("D_i of shamir id %d is not on curve", shamirId)
		}
		E_i := receivedMessage.Ei
		if E_i.IsIdentity() {
			return nil, nil, errors.Errorf("E_i of shamir id %d is at infinity", shamirId)
		}
		if !E_i.IsOnCurve() {
			return nil, nil, errors.Errorf("E_i of shamir id %d is not on curve", shamirId)
		}

		D_alpha[senderIdentityKey] = D_i
		E_alpha[senderIdentityKey] = E_i
	}
	return D_alpha, E_alpha, nil
}

func Helper_ProducePartialSignature(
	participant frost.Participant,
	sessionParticipants []integration.IdentityKey,
	signingKeyShare *frost.SigningKeyShare,
	d_i, e_i curves.Scalar,
	D_alpha, E_alpha map[integration.IdentityKey]curves.Point,
	shamirIdToIdentityKey map[int]integration.IdentityKey,
	identityKeyToShamirId map[integration.IdentityKey]int,
	aggregationParameter *aggregation.SignatureAggregatorParameters,
	message []byte,
) (*frost.PartialSignature, error) {
	cohortConfig := participant.GetCohortConfig()
	myShamirId := participant.GetShamirId()
	R := cohortConfig.CipherSuite.Curve.Point.Identity()
	r_i := cohortConfig.CipherSuite.Curve.Scalar.Zero()

	combinedDsAndEs := []byte{}
	for _, presentParty := range sessionParticipants {
		combinedDsAndEs = append(combinedDsAndEs, D_alpha[presentParty].ToAffineCompressed()...)
		combinedDsAndEs = append(combinedDsAndEs, E_alpha[presentParty].ToAffineCompressed()...)
	}

	R_js := map[integration.IdentityKey]curves.Point{}
	for _, participant := range sessionParticipants {
		shamirId := identityKeyToShamirId[participant]
		r_jHashComponents := []byte{byte(shamirId)}
		r_jHashComponents = append(r_jHashComponents, message...)
		r_jHashComponents = append(r_jHashComponents, combinedDsAndEs...)

		r_j := cohortConfig.CipherSuite.Curve.Scalar.Hash(r_jHashComponents)
		if shamirId == myShamirId {
			r_i = r_j
		}
		D_j, exists := D_alpha[participant]
		if !exists {
			return nil, errors.Errorf("could not find D_j for j=%d in D_alpha", shamirId)
		}
		E_j, exists := E_alpha[participant]
		if !exists {
			return nil, errors.Errorf("could not find E_j for j=%d in E_alpha", shamirId)
		}

		R_j := D_j.Add(E_j.Mul(r_j))
		R = R.Add(R_j)
		R_js[participant] = R_j
	}
	if R.IsIdentity() {
		return nil, errors.New("R is at infinity")
	}
	if r_i.IsZero() {
		return nil, errors.New("could not find r_i")
	}

	c, err := schnorr.ComputeFiatShamirChallege(cohortConfig.CipherSuite, [][]byte{
		R.ToAffineCompressed(), signingKeyShare.PublicKey.ToAffineCompressed(), message,
	})
	if err != nil {
		return nil, errors.Wrap(err, "converting hash to c failed")
	}

	shamir, err := sharing.NewShamir(cohortConfig.Threshold, cohortConfig.TotalParties, cohortConfig.CipherSuite.Curve)
	if err != nil {
		return nil, errors.Wrap(err, "could not initialize shamir methods")
	}
	presentPartyShamirIds := make([]int, len(sessionParticipants))
	for i := 0; i < len(sessionParticipants); i++ {
		presentPartyShamirIds[i] = identityKeyToShamirId[sessionParticipants[i]]
	}
	lagrangeCoefficients, err := shamir.LagrangeCoeffs(presentPartyShamirIds)
	if err != nil {
		return nil, errors.Wrap(err, "could not derive lagrange coefficients")
	}

	lambda_i, exists := lagrangeCoefficients[myShamirId]
	if !exists {
		return nil, errors.New("could not find my lagrange coefficient")
	}

	eiri := e_i.Mul(r_i)
	lambda_isic := lambda_i.Mul(signingKeyShare.Share.Mul(c))
	z_i := d_i.Add(eiri.Add(lambda_isic))

	if participant.IsSignatureAggregator() {
		if aggregationParameter == nil {
			return nil, errors.New("aggregation parameter is nil when the party is signature aggregator")
		}
		aggregationParameter.Z_i = z_i
		aggregationParameter.R = R
		aggregationParameter.R_js = R_js
		aggregationParameter.D_alpha = D_alpha
		aggregationParameter.E_alpha = E_alpha
	}

	return &frost.PartialSignature{
		Zi: z_i,
	}, nil
}
