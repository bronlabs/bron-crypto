package testutils

import (
	"bytes"
	crand "crypto/rand"
	"encoding/json"
	"hash"
	"sort"

	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton/pkg/base/curves"
	"github.com/copperexchange/krypton/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton/pkg/base/protocols"
	"github.com/copperexchange/krypton/pkg/base/types"
	"github.com/copperexchange/krypton/pkg/base/types/integration"
	"github.com/copperexchange/krypton/pkg/signatures/schnorr"
	"github.com/copperexchange/krypton/pkg/transcripts"
	"github.com/copperexchange/krypton/pkg/transcripts/hagrid"
)

type TestIdentityKey struct {
	curve  curves.Curve
	signer *schnorr.Signer
	h      func() hash.Hash

	_ types.Incomparable
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
	if err := schnorr.Verify(cipherSuite, schnorrPublicKey, message, schnorrSignature); err != nil {
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
		identity, err := MakeIdentity(cipherSuite, nil)
		identities[i] = identity
		if err != nil {
			return nil, err
		}
	}

	sortedIdentities := integration.ByPublicKey(identities)
	sort.Sort(sortedIdentities)
	return sortedIdentities, nil
}

func MakeIdentity(cipherSuite *integration.CipherSuite, secret curves.Scalar) (integration.IdentityKey, error) {
	signer, err := schnorr.NewSigner(cipherSuite, secret, crand.Reader)
	if err != nil {
		return nil, err
	}

	return &TestIdentityKey{
		curve:  cipherSuite.Curve,
		signer: signer,
		h:      cipherSuite.Hash,
	}, nil
}

func MakeCohortProtocol(cipherSuite *integration.CipherSuite, protocol protocols.Protocol, identities []integration.IdentityKey, threshold int, signatureAggregators []integration.IdentityKey) (cohortConfig *integration.CohortConfig, err error) {
	if threshold > len(identities) {
		return nil, errors.Errorf("invalid t=%d, n=%d", threshold, len(identities))
	}
	parties := append([]integration.IdentityKey{}, identities...)
	aggregators := append([]integration.IdentityKey{}, signatureAggregators...)
	cohortConfig = &integration.CohortConfig{
		CipherSuite:  cipherSuite,
		Participants: hashset.NewHashSet(parties),
		Protocol: &integration.ProtocolConfig{
			Name:                 protocol,
			Threshold:            threshold,
			TotalParties:         len(parties),
			SignatureAggregators: hashset.NewHashSet(aggregators),
		},
	}

	if err := cohortConfig.Validate(); err != nil {
		return nil, err
	}

	return cohortConfig, nil
}

func MakeTranscripts(label string, identities []integration.IdentityKey) (allTranscripts []transcripts.Transcript) {
	allTranscripts = make([]transcripts.Transcript, len(identities))
	for i := range identities {
		allTranscripts[i] = hagrid.NewTranscript(label, nil)
	}
	return allTranscripts
}

func TranscriptAtSameState(label string, allTranscripts []transcripts.Transcript) (bool, error) {
	for i := 0; i < len(allTranscripts); i++ {
		l, err := allTranscripts[i].ExtractBytes(label, 32)
		if err != nil {
			return false, err
		}
		for j := i + 1; j < len(allTranscripts); j++ {
			r, err := allTranscripts[j].ExtractBytes(label, 32)
			if err != nil {
				return false, err
			}
			if !bytes.Equal(l, r) {
				return false, nil
			}
		}
	}

	return true, nil
}
