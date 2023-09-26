package testutils

import (
	"bytes"
	crand "crypto/rand"
	"sort"

	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/protocols"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr/vanilla"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

type TestIdentityKey struct {
	suite      *integration.CipherSuite
	privateKey *schnorr.PrivateKey
	publicKey  *schnorr.PublicKey

	_ types.Incomparable
}

var _ integration.IdentityKey = (*TestIdentityKey)(nil)

func (k *TestIdentityKey) PublicKey() curves.Point {
	return k.publicKey.A
}

func (k *TestIdentityKey) Hash() [32]byte {
	return sha3.Sum256(k.PublicKey().ToAffineCompressed())
}

func (k *TestIdentityKey) Sign(message []byte) []byte {
	signer, err := schnorr.NewSigner(k.suite, k.privateKey)
	if err != nil {
		panic(err)
	}
	signature, err := signer.Sign(message, crand.Reader)
	if err != nil {
		panic(err)
	}
	return bytes.Join([][]byte{signature.R.ToAffineCompressed(), signature.S.Bytes()}, nil)
}

func (k *TestIdentityKey) Verify(signature []byte, publicKey curves.Point, message []byte) error {
	r := k.suite.Curve.Point().Identity()
	r, err := r.FromAffineCompressed(signature[:len(r.ToAffineCompressed())])
	if err != nil {
		return err
	}
	s := k.suite.Curve.Scalar().Zero()
	switch len(s.Bytes()) {
	case curves.WideFieldBytes:
		s, err = s.SetBytesWide(signature[len(r.ToAffineCompressed()):])
	case curves.FieldBytes:
		s, err = s.SetBytes(signature[len(r.ToAffineCompressed()):])
	default:
		err = errs.NewSerializationError("cannot deserialize signature")
	}
	if err != nil {
		return errs.NewSerializationError("cannot deserialize signature")
	}

	schnorrSignature := &schnorr.Signature{
		R: r,
		S: s,
	}
	schnorrPublicKey := &schnorr.PublicKey{
		A: publicKey,
	}
	if err := schnorr.Verify(k.suite, schnorrPublicKey, message, schnorrSignature); err != nil {
		return errors.Wrap(err, "could not verify schnorr signature")
	}
	return nil
}

func MakeTestIdentities(cipherSuite *integration.CipherSuite, n int) (identities []integration.IdentityKey, err error) {
	if err := cipherSuite.Validate(); err != nil {
		return nil, err
	}
	if n <= 0 {
		return nil, errors.Errorf("invalid number of identities: %d", n)
	}

	identities = make([]integration.IdentityKey, n)
	for i := 0; i < len(identities); i++ {
		identity, err := MakeTestIdentity(cipherSuite, nil)
		identities[i] = identity
		if err != nil {
			return nil, err
		}
	}

	sortedIdentities := integration.ByPublicKey(identities)
	sort.Sort(sortedIdentities)
	return sortedIdentities, nil
}

func MakeTestIdentity(cipherSuite *integration.CipherSuite, secret curves.Scalar) (integration.IdentityKey, error) {
	var sk *schnorr.PrivateKey
	var pk *schnorr.PublicKey
	var err error
	if secret != nil {
		pk, sk, err = schnorr.NewKeys(secret)
	} else {
		pk, sk, err = schnorr.KeyGen(cipherSuite.Curve, crand.Reader)
	}
	if err != nil {
		return nil, err
	}

	return &TestIdentityKey{
		suite:      cipherSuite,
		privateKey: sk,
		publicKey:  pk,
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
