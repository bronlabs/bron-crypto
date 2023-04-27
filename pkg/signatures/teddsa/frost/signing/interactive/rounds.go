package interactive

import (
	"sort"

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
	ic.state.d_i = ic.CohortConfig.CipherSuite.Curve.Scalar.Random(ic.reader)
	ic.state.e_i = ic.CohortConfig.CipherSuite.Curve.Scalar.Random(ic.reader)
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
	partialSignature, err := ic.Helper_ProducePartialSignature(D_alpha, E_alpha, message)
	if err != nil {
		return nil, errors.Wrap(err, "could not produce partial signature")
	}
	ic.round++
	return partialSignature, nil
}

func (ic *InteractiveCosigner) Aggregate(partialSignatures map[integration.IdentityKey]*frost.PartialSignature) (*frost.Signature, error) {
	if ic.round != 3 {
		return nil, errors.New("round mismatch")
	}
	aggregator, err := aggregation.NewSignatureAggregator(ic.MyIdentityKey, ic.CohortConfig, ic.SigningKeyShare.PublicKey, ic.PublicKeyShares, ic.state.S, ic.ShamirIdToIdentityKey, ic.state.aggregation)
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
	ic.state.S = make([]int, len(round1output))
	i := 0
	for identityKey := range round1output {
		ic.state.S[i] = ic.IdentityKeyToShamirId[identityKey]
		i++
	}
	sort.Ints(ic.state.S)

	D_alpha = map[integration.IdentityKey]curves.Point{}
	E_alpha = map[integration.IdentityKey]curves.Point{}

	for _, shamirId := range ic.state.S {
		senderIdentityKey, exists := ic.ShamirIdToIdentityKey[shamirId]
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

func (ic *InteractiveCosigner) Helper_ProducePartialSignature(D_alpha, E_alpha map[integration.IdentityKey]curves.Point, message []byte) (*frost.PartialSignature, error) {
	R := ic.CohortConfig.CipherSuite.Curve.Point.Identity()
	r_i := ic.CohortConfig.CipherSuite.Curve.Scalar.Zero()

	combinedDsAndEs := []byte{}
	for _, presentPartyShamirID := range ic.state.S {
		currentParticipant := ic.ShamirIdToIdentityKey[presentPartyShamirID]
		combinedDsAndEs = append(combinedDsAndEs, D_alpha[currentParticipant].ToAffineCompressed()...)
	}
	for _, presentPartyShamirID := range ic.state.S {
		currentParticipant := ic.ShamirIdToIdentityKey[presentPartyShamirID]
		combinedDsAndEs = append(combinedDsAndEs, E_alpha[currentParticipant].ToAffineCompressed()...)
	}

	R_js := map[integration.IdentityKey]curves.Point{}
	for _, j := range ic.state.S {
		r_jHashComponents := []byte{byte(j)}
		r_jHashComponents = append(r_jHashComponents, message...)
		r_jHashComponents = append(r_jHashComponents, combinedDsAndEs...)

		r_j := ic.CohortConfig.CipherSuite.Curve.Scalar.Hash(r_jHashComponents)
		if j == ic.MyShamirId {
			r_i = r_j
		}
		jIdentityKey, exists := ic.ShamirIdToIdentityKey[j]
		if !exists {
			return nil, errors.Errorf("could not find the identity key of cosigner with shamir id %d", j)
		}
		D_j, exists := D_alpha[jIdentityKey]
		if !exists {
			return nil, errors.Errorf("could not find D_j for j=%d in D_alpha", j)
		}
		E_j, exists := E_alpha[jIdentityKey]
		if !exists {
			return nil, errors.Errorf("could not find E_j for j=%d in E_alpha", j)
		}

		R_j := D_j.Add(E_j.Mul(r_j))
		R = R.Add(R_j)
		R_js[jIdentityKey] = R_j
	}
	if R.IsIdentity() {
		return nil, errors.New("R is at infinity")
	}
	if r_i.IsZero() {
		return nil, errors.New("could not find r_i")
	}

	c, err := schnorr.ComputeFiatShamirChallege(ic.CohortConfig.CipherSuite, [][]byte{
		R.ToAffineCompressed(), ic.SigningKeyShare.PublicKey.ToAffineCompressed(), message,
	})
	if err != nil {
		return nil, errors.Wrap(err, "converting hash to c failed")
	}

	shamir, err := sharing.NewShamir(uint32(ic.CohortConfig.Threshold), uint32(ic.CohortConfig.TotalParties), ic.CohortConfig.CipherSuite.Curve)
	if err != nil {
		return nil, errors.Wrap(err, "could not initialize shamir methods")
	}
	lagrangeCoefficients, err := shamir.LagrangeCoeffs(ic.state.S)
	if err != nil {
		return nil, errors.Wrap(err, "could not derive lagrange coefficients")
	}

	lambda_i, exists := lagrangeCoefficients[ic.MyShamirId]
	if !exists {
		return nil, errors.New("could not find my lagrange coefficient")
	}

	eiri := ic.state.e_i.Mul(r_i)
	lambda_isic := lambda_i.Mul(ic.SigningKeyShare.Share.Mul(c))
	z_i := ic.state.d_i.Add(eiri.Add(lambda_isic))

	ic.state.d_i = nil
	ic.state.e_i = nil

	if ic.IsSignatureAggregator() {
		ic.state.aggregation = &aggregation.SignatureAggregatorParameters{
			Message: message,
			Z_i:     z_i,
			R:       R,
			R_js:    R_js,
			D_alpha: D_alpha,
			E_alpha: E_alpha,
		}
	}

	return &frost.PartialSignature{
		Zi: z_i,
	}, nil
}
