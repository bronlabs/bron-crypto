package testutils

import (
	"bytes"
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"

	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/protocols"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	schnorr "github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr/vanilla"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

type TestAuthKey struct {
	suite      *integration.CipherSuite
	privateKey *schnorr.PrivateKey
	publicKey  *schnorr.PublicKey

	_ types.Incomparable
}

type TestIdentityKey = TestAuthKey

var _ integration.IdentityKey = (*TestAuthKey)(nil)
var _ integration.AuthKey = (*TestAuthKey)(nil)

func (k *TestAuthKey) PrivateKey() curves.Scalar {
	return k.privateKey.S
}

func (k *TestAuthKey) PublicKey() curves.Point {
	return k.publicKey.A
}

func (k *TestAuthKey) Hash() [32]byte {
	return sha256.Sum256(k.PublicKey().ToAffineCompressed())
}

func (k *TestAuthKey) Sign(message []byte) []byte {
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

func (k *TestAuthKey) Verify(signature, message []byte) error {
	r := k.suite.Curve.Point().Identity()
	r, err := r.FromAffineCompressed(signature[:len(r.ToAffineCompressed())])
	if err != nil {
		return errs.NewSerialisation("cannot deserialize signature")
	}
	s := k.suite.Curve.Scalar().Zero()
	switch len(s.Bytes()) {
	case base.WideFieldBytes:
		s, err = s.SetBytesWide(signature[len(r.ToAffineCompressed()):])
	case base.FieldBytes:
		s, err = s.SetBytes(signature[len(r.ToAffineCompressed()):])
	default:
		err = errs.NewSerialisation("cannot deserialize signature")
	}
	if err != nil {
		return errs.NewSerialisation("cannot deserialize signature")
	}

	schnorrSignature := &schnorr.Signature{
		R: r,
		S: s,
	}
	schnorrPublicKey := &schnorr.PublicKey{
		A: k.publicKey.A,
	}
	if err := schnorr.Verify(k.suite, schnorrPublicKey, message, schnorrSignature); err != nil {
		return errs.WrapVerificationFailed(err, "could not verify schnorr signature")
	}
	return nil
}

var _ integration.AuthKey = (*TestDeterministicAuthKey)(nil)

type TestDeterministicAuthKey struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

func (k *TestDeterministicAuthKey) PrivateKey() curves.Scalar {
	hashed := sha512.Sum512(k.privateKey.Seed())
	result, _ := edwards25519.NewScalar().SetBytesWithClamping(hashed[:32])
	return result
}

func (k *TestDeterministicAuthKey) PublicKey() curves.Point {
	result, err := edwards25519.New().Point().FromAffineCompressed(k.publicKey)
	if err != nil {
		panic(err)
	}
	return result
}

func (k *TestDeterministicAuthKey) Hash() [32]byte {
	return sha3.Sum256(k.PublicKey().ToAffineCompressed())
}

func (k *TestDeterministicAuthKey) Sign(message []byte) []byte {
	signature, err := k.privateKey.Sign(crand.Reader, message, &ed25519.Options{})
	if err != nil {
		panic(err)
	}
	return signature
}

func (k *TestDeterministicAuthKey) Verify(signature, message []byte) error {
	if ok := ed25519.Verify(k.PublicKey().ToAffineCompressed(), message, signature); !ok {
		return errs.NewFailed("invalid signature")
	}
	return nil
}

type HexBytes []byte

func (h *HexBytes) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return errs.WrapFailed(err, "could not unmarshal hex bytes")
	}

	if s == "" {
		*h = nil
		return nil
	}

	hexStr := strings.TrimPrefix(s, "0x")

	decoded, err := hex.DecodeString(hexStr)
	if err != nil {
		return errs.WrapFailed(err, "could not decode hex bytes")
	}
	*h = decoded
	return nil
}

func MakeTestIdentities(cipherSuite *integration.CipherSuite, n int) (identities []integration.IdentityKey, err error) {
	if err := cipherSuite.Validate(); err != nil {
		return nil, errs.WrapInvalidArgument(err, "invalid cipher suite")
	}
	if n <= 0 {
		return nil, errs.NewInvalidLength("invalid number of identities: %d", n)
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
		return nil, errs.WrapFailed(err, "could not generate schnorr key pair")
	}

	return &TestAuthKey{
		suite:      cipherSuite,
		privateKey: sk,
		publicKey:  pk,
	}, nil
}

func MakeTestAuthKeys(cipherSuite *integration.CipherSuite, n int) (authKeys []integration.AuthKey, err error) {
	var ok bool
	result := make([]integration.AuthKey, n)
	out, err := MakeTestIdentities(cipherSuite, n)
	if err != nil {
		return nil, err
	}
	for i, k := range out {
		result[i], ok = k.(integration.AuthKey)
		if !ok {
			return nil, errs.NewInvalidType("identity key is not auth key #%d", i)
		}
	}
	return result, nil
}

func MakeTestAuthKey(cipherSuite *integration.CipherSuite, secret curves.Scalar) (integration.AuthKey, error) {
	result, err := MakeTestIdentity(cipherSuite, secret)
	if err != nil {
		return nil, err
	}
	authKey, ok := result.(integration.AuthKey)
	if !ok {
		return nil, errs.NewInvalidType("identity key is not auth key")
	}
	return authKey, nil
}

func MakeDeterministicTestIdentities(n int) (identities []integration.IdentityKey, err error) {
	result := make([]integration.IdentityKey, n)
	for i := 0; i < n; i++ {
		publicKey, privateKey, err := ed25519.GenerateKey(crand.Reader)
		if err != nil {
			return nil, err
		}
		result[i], err = MakeDeterministicTestIdentity(privateKey, publicKey)
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

func MakeDeterministicTestIdentity(privateKey ed25519.PrivateKey, publicKey ed25519.PublicKey) (integration.IdentityKey, error) {
	return &TestDeterministicAuthKey{
		privateKey: privateKey,
		publicKey:  publicKey,
	}, nil
}

func MakeDeterministicTestAuthKeys(n int) (authKeys []integration.AuthKey, err error) {
	var ok bool
	result := make([]integration.AuthKey, n)
	out, err := MakeDeterministicTestIdentities(n)
	if err != nil {
		return nil, err
	}
	for i, k := range out {
		result[i], ok = k.(integration.AuthKey)
		if !ok {
			return nil, errs.NewInvalidType("identity key is not auth key #%d", i)
		}
	}
	return result, nil
}

func MakeDeterministicTestAuthKey(privateKey ed25519.PrivateKey, publicKey ed25519.PublicKey) (integration.AuthKey, error) {
	result, err := MakeDeterministicTestIdentity(privateKey, publicKey)
	if err != nil {
		return nil, err
	}
	authKey, ok := result.(integration.AuthKey)
	if !ok {
		return nil, errs.NewInvalidType("identity key is not auth key")
	}
	return authKey, nil
}

func MakeCohortProtocol(cipherSuite *integration.CipherSuite, protocol protocols.Protocol, identities []integration.IdentityKey, threshold int, signatureAggregators []integration.IdentityKey) (cohortConfig *integration.CohortConfig, err error) {
	if threshold > len(identities) {
		return nil, errs.NewInvalidLength("invalid t=%d, n=%d", threshold, len(identities))
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
		return nil, errs.WrapInvalidArgument(err, "invalid cohort config")
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
			return false, errs.WrapFailed(err, "could not extract transcript")
		}
		for j := i + 1; j < len(allTranscripts); j++ {
			r, err := allTranscripts[j].ExtractBytes(label, 32)
			if err != nil {
				return false, errs.WrapFailed(err, "could not extract transcript")
			}
			if !bytes.Equal(l, r) {
				return false, nil
			}
		}
	}

	return true, nil
}
