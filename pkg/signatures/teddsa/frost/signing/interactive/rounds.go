package interactive_signing

import (
	crand "crypto/rand"
	"crypto/sha512"
	"fmt"
	"sort"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/sharing"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost/signing/aggregation"
	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"
)

var H = sha512.New512_256()

type Round1Broadcast struct {
	Di curves.Point
	Ei curves.Point
}

func (ic *InteractiveCosigner) Round1() (*Round1Broadcast, error) {
	if ic.round != 1 {
		return nil, errors.New("round mismatch")
	}
	ic.state.d_i = ic.CohortConfig.Curve.Scalar.Random(crand.Reader)
	ic.state.e_i = ic.CohortConfig.Curve.Scalar.Random(crand.Reader)
	ic.state.D_i = ic.CohortConfig.Curve.ScalarBaseMult(ic.state.d_i)
	ic.state.E_i = ic.CohortConfig.Curve.ScalarBaseMult(ic.state.e_i)
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
	partialSignature, err := ic.Helper_ProducePartialSignature(round1output, D_alpha, E_alpha, message)
	if err != nil {
		return nil, errors.Wrap(err, "could not produce partial signature")
	}
	ic.round++
	return partialSignature, nil
}

func Aggregate(partialSignatures map[integration.IdentityKey]*frost.PartialSignature, aggregationParameters *aggregation.SignatureAggregatorParameters) (*frost.Signature, error) {
	return nil, nil
}

func (ic *InteractiveCosigner) processNonceCommitmentOnline(round1output map[integration.IdentityKey]*Round1Broadcast) (D_alpha []curves.Point, E_alpha []curves.Point, err error) {
	round1output[ic.MyIdentityKey] = &Round1Broadcast{
		Di: ic.state.D_i,
		Ei: ic.state.E_i,
	}
	ic.state.S = make([]int, len(round1output))
	i := 0
	for identityKey := range round1output {
		ic.state.S[i] = ic.identityKeyToShamirId[identityKey]
		i++
	}
	sort.Ints(ic.state.S)

	D_alpha = make([]curves.Point, len(ic.state.S))
	E_alpha = make([]curves.Point, len(ic.state.S))

	i = 0
	for _, shamirId := range ic.state.S {
		senderIdentityKey, exists := ic.shamirIdToIdentityKey[shamirId]
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

		D_alpha[i] = D_i
		E_alpha[i] = E_i
		i++
	}
	return D_alpha, E_alpha, nil
}

func (ic *InteractiveCosigner) Helper_ProducePartialSignature(round1output map[integration.IdentityKey]*Round1Broadcast, D_alpha, E_alpha []curves.Point, message []byte) (*frost.PartialSignature, error) {
	R := ic.CohortConfig.Curve.Point.Identity()
	r_i := ic.CohortConfig.Curve.Scalar.Zero()
	for _, j := range ic.state.S {
		hasher := sha3.New256()
		if _, err := hasher.Write([]byte(fmt.Sprintf("%d", j))); err != nil {
			return nil, errors.Wrap(err, "could not write present participant into hasher")
		}
		if _, err := hasher.Write(message); err != nil {
			return nil, errors.Wrap(err, "could not write message into hasher")
		}
		for _, D := range D_alpha {
			if _, err := hasher.Write(D.ToAffineCompressed()); err != nil {
				return nil, errors.Wrap(err, "could not write an element of D_alpha into hasher")
			}
		}
		for _, E := range D_alpha {
			if _, err := hasher.Write(E.ToAffineCompressed()); err != nil {
				return nil, errors.Wrap(err, "could not write an element of E_alpha into hasher")
			}
		}

		r_j := ic.CohortConfig.Curve.Scalar.Zero()
		var err error
		if ic.CohortConfig.Curve.Name == curves.ED25519().Name {
			scalar := &curves.ScalarEd25519{}
			r_j, err = scalar.SetBytesClamping(hasher.Sum(nil))
			if err != nil {
				return nil, errors.Wrap(err, "converting hash to r_j failed")
			}
		} else {
			r_j, err = ic.CohortConfig.Curve.Scalar.SetBytes(hasher.Sum(nil))
			if err != nil {
				return nil, errors.Wrap(err, "converting hash to r_j failed")
			}
		}

		if j == ic.MyShamirId {
			r_i = r_j
		}

		currentCosignerIdentityKey, exists := ic.shamirIdToIdentityKey[j]
		if !exists {
			return nil, errors.Errorf("could not find the identity key of cosigner with shamir id %d", j)
		}

		message, exists := round1output[currentCosignerIdentityKey]
		if !exists {
			return nil, errors.Errorf("do not have a message from cosigner with shamir id %d", j)
		}

		R_j := message.Di.Add(message.Ei.Mul(r_j))
		R = R.Add(R_j)
	}
	if R.IsIdentity() {
		return nil, errors.New("R is at infinity")
	}
	if r_i.IsZero() {
		return nil, errors.New("could not find r_i")
	}
	challengeHasher := ic.CohortConfig.Hash()
	if _, err := challengeHasher.Write(R.ToAffineCompressed()); err != nil {
		return nil, errors.Wrap(err, "could not write R to challenge hasher")
	}
	if _, err := challengeHasher.Write(ic.SigningKeyShare.PublicKey.ToAffineCompressed()); err != nil {
		return nil, errors.Wrap(err, "could not write public key to challenge hasher")
	}
	if _, err := challengeHasher.Write(message); err != nil {
		return nil, errors.Wrap(err, "could not write the message to challenge hasher")
	}
	c := ic.CohortConfig.Curve.Scalar.Zero()
	var err error
	if ic.CohortConfig.Curve.Name == curves.ED25519().Name {
		scalar := &curves.ScalarEd25519{}
		c, err = scalar.SetBytesClamping(challengeHasher.Sum(nil))
		if err != nil {
			return nil, errors.Wrap(err, "converting hash to c failed")
		}
	} else {
		c, err = ic.CohortConfig.Curve.Scalar.SetBytes(challengeHasher.Sum(nil))
		if err != nil {
			return nil, errors.Wrap(err, "converting hash to c failed")
		}
	}

	shamir, err := sharing.NewShamir(uint32(ic.CohortConfig.Threshold), uint32(ic.CohortConfig.TotalParties), ic.CohortConfig.Curve)
	if err != nil {
		return nil, errors.Wrap(err, "could not initialize shamir methods")
	}
	shamirIdsUint32 := make([]uint32, len(ic.state.S))
	for i, shamirId := range ic.state.S {
		shamirIdsUint32[i] = uint32(shamirId)
	}
	lagrangeCoefficients, err := shamir.LagrangeCoeffs(shamirIdsUint32)
	if err != nil {
		return nil, errors.Wrap(err, "could not derive lagrange coefficients")
	}

	lambda_i, exists := lagrangeCoefficients[uint32(ic.MyShamirId)]
	if !exists {
		return nil, errors.New("could not find my lagrange coefficient")
	}
	ei_ri := ic.state.e_i.Mul(r_i)
	lambdai_si_c := lambda_i.Mul(ic.SigningKeyShare.Share.Mul(c))
	z_i := ic.state.d_i.Add(ei_ri.Add(lambdai_si_c))

	ic.state.d_i = nil
	ic.state.e_i = nil

	if ic.IsSignatureAggregator() {
		ic.state.aggregation = &aggregation.SignatureAggregatorParameters{
			Message: message,
			Z_i:     z_i,
			R:       R,
			D_alpha: D_alpha,
			E_alpha: E_alpha,
		}
	}

	return &frost.PartialSignature{
		Zi: z_i,
	}, nil
}
