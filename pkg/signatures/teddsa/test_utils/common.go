package test_utils

import (
	crand "crypto/rand"
	"encoding/json"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/protocol"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/schnorr"
	"github.com/pkg/errors"
	"hash"
)

type TestIdentityKey struct {
	curve  *curves.Curve
	signer *schnorr.Signer
	h      func() hash.Hash
}

func (k *TestIdentityKey) PublicKey() curves.Point {
	return k.signer.PublicKey.Y
}
func (k *TestIdentityKey) Sign(message []byte) []byte {
	signature, err := k.signer.Sign(message)
	if err != nil {
		panic(err)
	}
	result, err := json.Marshal(signature)
	if err != nil {
		panic(err)
	}
	return result
}
func (k *TestIdentityKey) Verify(signature []byte, publicKey curves.Point, message []byte) error {
	return errors.New("not implemented")
}

func MakeIdentities(cipherSuite *integration.CipherSuite, n int) (identities []integration.IdentityKey, err error) {
	if err = cipherSuite.Validate(); err != nil {
		return nil, err
	}
	if n <= 0 {
		return nil, errors.Errorf("invalid number of identities: %d", n)
	}

	identities = make([]integration.IdentityKey, n)
	for i := 0; i < len(identities); i++ {
		signer, err := schnorr.NewSigner(cipherSuite, nil, crand.Reader, nil)
		if err != nil {
			return nil, err
		}

		identities[i] = &TestIdentityKey{
			curve:  cipherSuite.Curve,
			signer: signer,
			h:      cipherSuite.Hash,
		}
	}

	return identities, nil
}

func MakeCohort(cipherSuite *integration.CipherSuite, protocol protocol.Protocol, identities []integration.IdentityKey, threshold int, signatureAggregators []integration.IdentityKey) (cohortConfig *integration.CohortConfig, err error) {
	if threshold > len(identities) {
		return nil, errors.Errorf("invalid t=%d, n=%d", threshold, len(identities))
	}

	parties := append([]integration.IdentityKey{}, identities...)
	aggregators := append([]integration.IdentityKey{}, signatureAggregators...)
	cohortConfig = &integration.CohortConfig{
		CipherSuite:          cipherSuite,
		Protocol:             protocol,
		Threshold:            threshold,
		TotalParties:         len(parties),
		Participants:         parties,
		SignatureAggregators: aggregators,
	}

	if err = cohortConfig.Validate(); err != nil {
		return nil, err
	}

	return cohortConfig, nil
}
