package test_utils

import (
	"bytes"
	crand "crypto/rand"
	"encoding/json"
	"hash"

	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/core/protocols"
	"github.com/copperexchange/knox-primitives/pkg/signatures/schnorr"
	"github.com/copperexchange/knox-primitives/pkg/transcripts"
	"github.com/copperexchange/knox-primitives/pkg/transcripts/merlin"
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

func (k *TestIdentityKey) Hash() [32]byte {
	return sha3.Sum256(k.signer.PublicKey.Y.ToAffineCompressed())
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
	if err := cipherSuite.Validate(); err != nil {
		return nil, err
	}
	if n <= 0 {
		return nil, errors.Errorf("invalid number of identities: %d", n)
	}

	identities = make([]integration.IdentityKey, n)
	for i := 0; i < len(identities); i++ {
		identity, err := MakeIdentity(cipherSuite, nil, nil)
		identities[i] = identity
		if err != nil {
			return nil, err
		}
	}

	identities = integration.SortIdentityKeys(identities)

	return identities, nil
}

func MakeIdentity(cipherSuite *integration.CipherSuite, secret curves.Scalar, options *schnorr.Options) (integration.IdentityKey, error) {
	signer, err := schnorr.NewSigner(cipherSuite, secret, crand.Reader, options)
	if err != nil {
		return nil, err
	}

	return &TestIdentityKey{
		curve:  cipherSuite.Curve,
		signer: signer,
		h:      cipherSuite.Hash,
	}, nil
}

func MakeCohort(cipherSuite *integration.CipherSuite, protocol protocols.Protocol, identities []integration.IdentityKey, threshold int, signatureAggregators []integration.IdentityKey) (cohortConfig *integration.CohortConfig, err error) {
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

	if err := cohortConfig.Validate(); err != nil {
		return nil, err
	}

	return cohortConfig, nil
}

func MakeTranscripts(label string, identities []integration.IdentityKey) (allTranscripts []transcripts.Transcript) {
	allTranscripts = make([]transcripts.Transcript, len(identities))
	for i := range identities {
		allTranscripts[i] = merlin.NewTranscript(label)
	}
	return allTranscripts
}

func TranscriptAtSameState(label string, allTranscripts []transcripts.Transcript) bool {
	for i := 0; i < len(allTranscripts); i++ {
		l := allTranscripts[i].ExtractBytes(label, 32)
		for j := i + 1; j < len(allTranscripts); j++ {
			r := allTranscripts[j].ExtractBytes(label, 32)
			if !bytes.Equal(l, r) {
				return false
			}
		}
	}

	return true
}
