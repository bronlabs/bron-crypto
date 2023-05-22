package test_utils

import (
	crand "crypto/rand"
	"encoding/json"
	"hash"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/protocol"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/schnorr"
	"github.com/pkg/errors"
)

type TestIdentityKey struct {
	curve  *curves.Curve
	signer *schnorr.Signer
	h      func() hash.Hash
}

var _ integration.IdentityKey = (*TestIdentityKey)(nil)

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
	cipherSuite := &integration.CipherSuite{
		Curve: k.curve,
		Hash:  k.h,
	}
	schnorrSignature := &schnorr.Signature{}
	if err := json.Unmarshal(signature, &schnorrSignature); err != nil {
		return errors.Wrap(err, "could not unmarshal signature")
	}
	schnorrPublicKey := &schnorr.PublicKey{
		Curve: k.curve,
		Y:     k.PublicKey(),
	}
	if err := schnorr.Verify(cipherSuite, schnorrPublicKey, message, schnorrSignature, nil); err != nil {
		return errors.Wrap(err, "could not verify schnorr signature")
	}
	return nil
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

func MakeCohort(cipherSuite *integration.CipherSuite, protocol protocol.Protocol, identities []integration.IdentityKey, threshold int) (cohortConfig *integration.CohortConfig, err error) {
	if threshold > len(identities) {
		return nil, errors.Errorf("invalid t=%d, n=%d", threshold, len(identities))
	}

	cohortConfig = &integration.CohortConfig{
		CipherSuite:          cipherSuite,
		Protocol:             protocol,
		Threshold:            threshold,
		TotalParties:         len(identities),
		Participants:         identities,
		SignatureAggregators: identities,
		PreSignatureComposer: identities[0],
	}

	if err = cohortConfig.Validate(); err != nil {
		return nil, err
	}

	return cohortConfig, nil
}
