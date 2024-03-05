package testutils

import (
	"bytes"
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"slices"
	"sort"
	"strings"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr"
	vanillaSchnorr "github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr/vanilla"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

type TestAuthKey struct {
	suite      types.SignatureProtocol
	privateKey *vanillaSchnorr.PrivateKey
	publicKey  *vanillaSchnorr.PublicKey

	_ ds.Incomparable
}

type TestIdentityKey = TestAuthKey

var _ types.IdentityKey = (*TestAuthKey)(nil)
var _ types.AuthKey = (*TestAuthKey)(nil)

func (k *TestAuthKey) PrivateKey() curves.Scalar {
	return k.privateKey.S
}

func (k *TestAuthKey) PublicKey() curves.Point {
	return k.publicKey.A
}

func (k *TestAuthKey) HashCode() uint64 {
	return binary.BigEndian.Uint64(k.PublicKey().ToAffineCompressed())
}

func (k *TestAuthKey) Equal(rhs types.IdentityKey) bool {
	return subtle.ConstantTimeCompare(k.PublicKey().ToAffineCompressed(), rhs.PublicKey().ToAffineCompressed()) == 1
}

func (k *TestAuthKey) Sign(message []byte) []byte {
	signer, err := vanillaSchnorr.NewSigner(k.suite, k.privateKey)
	if err != nil {
		panic(err)
	}
	signature, err := signer.Sign(message, crand.Reader)
	if err != nil {
		panic(err)
	}
	return slices.Concat(signature.R.ToAffineCompressed(), signature.S.Bytes())
}

func (k *TestAuthKey) Verify(signature, message []byte) error {
	r := k.suite.Curve().Identity()
	r, err := r.FromAffineCompressed(signature[:len(r.ToAffineCompressed())])
	if err != nil {
		return errs.NewSerialisation("cannot deserialize signature")
	}
	s := k.suite.Curve().ScalarField().Zero()
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

	schnorrSignature := schnorr.NewSignature(schnorr.NewEdDsaCompatibleVariant(), nil, r, s)
	schnorrPublicKey := &vanillaSchnorr.PublicKey{
		A: k.publicKey.A,
	}
	if err := vanillaSchnorr.Verify(k.suite, schnorrPublicKey, message, schnorrSignature); err != nil {
		return errs.WrapVerification(err, "could not verify schnorr signature")
	}
	return nil
}

func (k *TestAuthKey) String() string {
	return fmt.Sprintf("%x", k.PublicKey().ToAffineCompressed())
}

func (*TestIdentityKey) MarshalJSON() ([]byte, error) {
	panic("not implemented")
}

var _ types.AuthKey = (*TestDeterministicAuthKey)(nil)

type TestDeterministicAuthKey struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

func (k *TestDeterministicAuthKey) PrivateKey() curves.Scalar {
	hashed := sha512.Sum512(k.privateKey.Seed())
	result, _ := edwards25519.NewScalar(0).SetBytesWithClampingLE(hashed[:32])
	return result
}

func (k *TestDeterministicAuthKey) PublicKey() curves.Point {
	result, err := edwards25519.NewCurve().Point().FromAffineCompressed(k.publicKey)
	if err != nil {
		panic(err)
	}
	return result
}

func (k *TestDeterministicAuthKey) HashCode() uint64 {
	return binary.BigEndian.Uint64(k.PublicKey().ToAffineCompressed())
}

func (k *TestDeterministicAuthKey) Equal(rhs types.IdentityKey) bool {
	return subtle.ConstantTimeCompare(k.PublicKey().ToAffineCompressed(), rhs.PublicKey().ToAffineCompressed()) == 1
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

func (k *TestDeterministicAuthKey) String() string {
	return fmt.Sprintf("%x", k.PublicKey().ToAffineCompressed())
}

func (*TestDeterministicAuthKey) MarshalJSON() ([]byte, error) {
	panic("not implemented")
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

type HexBytesArray [][]byte

func (h *HexBytesArray) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return errs.WrapFailed(err, "could not unmarshal hex bytes")
	}

	if s == "" {
		*h = nil
		return nil
	}

	hexes := strings.Split(s, ",")

	decoded := make([][]byte, len(hexes))

	for i, h := range hexes {
		var err error
		hexStr := strings.TrimPrefix(h, "0x")
		decoded[i], err = hex.DecodeString(hexStr)
		if err != nil {
			return errs.WrapFailed(err, "could not decode hex bytes")
		}
	}
	*h = decoded
	return nil
}

func MakeTestIdentities(cipherSuite types.SignatureProtocol, n int) (identities []types.IdentityKey, err error) {
	if err := types.ValidateSignatureProtocolConfig(cipherSuite); err != nil {
		return nil, errs.WrapValidation(err, "invalid cipher suite")
	}
	if n <= 0 {
		return nil, errs.NewValue("invalid number of identities: %d", n)
	}

	identities = make([]types.IdentityKey, n)
	for i := 0; i < len(identities); i++ {
		identity, err := MakeTestIdentity(cipherSuite, nil)
		identities[i] = identity
		if err != nil {
			return nil, err
		}
	}

	sortedIdentities := types.ByPublicKey(identities)
	sort.Sort(sortedIdentities)
	return sortedIdentities, nil
}

func MakeTestIdentity(cipherSuite types.SignatureProtocol, secret curves.Scalar) (types.IdentityKey, error) {
	var sk *vanillaSchnorr.PrivateKey
	var pk *vanillaSchnorr.PublicKey
	var err error
	if secret != nil {
		pk, sk, err = vanillaSchnorr.NewKeys(secret)
	} else {
		pk, sk, err = vanillaSchnorr.KeyGen(cipherSuite.Curve(), crand.Reader)
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

func MakeTestAuthKeys(cipherSuite types.SignatureProtocol, n int) (authKeys []types.AuthKey, err error) {
	var ok bool
	result := make([]types.AuthKey, n)
	out, err := MakeTestIdentities(cipherSuite, n)
	if err != nil {
		return nil, err
	}
	for i, k := range out {
		result[i], ok = k.(types.AuthKey)
		if !ok {
			return nil, errs.NewType("identity key is not auth key #%d", i)
		}
	}
	return result, nil
}

func MakeTestAuthKey(cipherSuite types.SignatureProtocol, secret curves.Scalar) (types.AuthKey, error) {
	result, err := MakeTestIdentity(cipherSuite, secret)
	if err != nil {
		return nil, err
	}
	authKey, ok := result.(types.AuthKey)
	if !ok {
		return nil, errs.NewType("identity key is not auth key")
	}
	return authKey, nil
}

func MakeDeterministicTestIdentities(n int) (identities []types.IdentityKey, err error) {
	result := make([]types.IdentityKey, n)
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

func MakeDeterministicTestIdentity(privateKey ed25519.PrivateKey, publicKey ed25519.PublicKey) (types.IdentityKey, error) {
	return &TestDeterministicAuthKey{
		privateKey: privateKey,
		publicKey:  publicKey,
	}, nil
}

func MakeDeterministicTestAuthKeys(n int) (authKeys []types.AuthKey, err error) {
	var ok bool
	result := make([]types.AuthKey, n)
	out, err := MakeDeterministicTestIdentities(n)
	if err != nil {
		return nil, err
	}
	for i, k := range out {
		result[i], ok = k.(types.AuthKey)
		if !ok {
			return nil, errs.NewType("identity key is not auth key #%d", i)
		}
	}
	return result, nil
}

func MakeDeterministicTestAuthKey(privateKey ed25519.PrivateKey, publicKey ed25519.PublicKey) (types.AuthKey, error) {
	result, err := MakeDeterministicTestIdentity(privateKey, publicKey)
	if err != nil {
		return nil, err
	}
	authKey, ok := result.(types.AuthKey)
	if !ok {
		return nil, errs.NewType("identity key is not auth key")
	}
	return authKey, nil
}

var _ types.SignatureProtocol = (*CipherSuite)(nil)

type CipherSuite struct {
	curve curves.Curve
	hash  func() hash.Hash

	_ ds.Incomparable
}

func (cs *CipherSuite) Curve() curves.Curve {
	return cs.curve
}

func (cs *CipherSuite) Hash() func() hash.Hash {
	return cs.hash
}

func (*CipherSuite) MarshalJSON() ([]byte, error) {
	panic("not implemented")
}

var _ types.ThresholdSignatureProtocol = (*Protocol)(nil)

type Protocol struct {
	curve                curves.Curve
	hash                 func() hash.Hash
	participants         ds.Set[types.IdentityKey]
	threshold            uint
	totalParties         uint
	signatureAggregators ds.Set[types.IdentityKey]
	presignatureComposer types.IdentityKey
}

func (p *Protocol) Curve() curves.Curve {
	return p.curve
}

func (p *Protocol) Hash() func() hash.Hash {
	return p.hash
}

func (p *Protocol) Participants() ds.Set[types.IdentityKey] {
	return p.participants
}

func (p *Protocol) Threshold() uint {
	return p.threshold
}

func (p *Protocol) TotalParties() uint {
	return p.totalParties
}

func (p *Protocol) SignatureAggregators() ds.Set[types.IdentityKey] {
	return p.signatureAggregators
}

func (p *Protocol) PreSignatureComposer() types.IdentityKey {
	return p.presignatureComposer
}

func (p *Protocol) CipherSuite() types.SignatureProtocol {
	return &CipherSuite{
		curve: p.curve,
		hash:  p.hash,
	}
}

func (*Protocol) MarshalJSON() ([]byte, error) {
	panic("not implemented")
}

func MakeGenericProtocol(curve curves.Curve) (types.GenericProtocol, error) {
	generic := &Protocol{curve: curve}
	if err := types.ValidateGenericProtocolConfig(generic); err != nil {
		return nil, errs.WrapValidation(err, "generic")
	}
	return generic, nil
}

func MakeMPCProtocol(curve curves.Curve, identities []types.IdentityKey) (types.MPCProtocol, error) {
	mpc := &Protocol{
		curve:        curve,
		participants: hashset.NewHashableHashSet(identities...),
	}
	if err := types.ValidateMPCProtocolConfig(mpc); err != nil {
		return nil, errs.WrapValidation(err, "mpc")
	}
	return mpc, nil
}

func MakeThresholdProtocol(curve curves.Curve, identities []types.IdentityKey, t int) (types.ThresholdProtocol, error) {
	participants := hashset.NewHashableHashSet(identities...)
	threshold := &Protocol{
		curve:        curve,
		participants: participants,
		threshold:    uint(t),
		totalParties: uint(participants.Size()),
	}
	if err := types.ValidateThresholdProtocolConfig(threshold); err != nil {
		return nil, errs.WrapValidation(err, "threshold")
	}
	return threshold, nil
}

func MakeSignatureProtocol(curve curves.Curve, h func() hash.Hash) (types.SignatureProtocol, error) {
	sig := &Protocol{
		curve: curve,
		hash:  h,
	}
	if err := types.ValidateSignatureProtocolConfig(sig); err != nil {
		return nil, errs.WrapValidation(err, "sig")
	}
	return sig, nil
}

func MakeThresholdSignatureProtocol(cipherSuite types.SignatureProtocol, identities []types.IdentityKey, t int, signatureAggregators []types.IdentityKey) (types.ThresholdSignatureProtocol, error) {
	participants := hashset.NewHashableHashSet(identities...)
	tsig := &Protocol{
		curve:                cipherSuite.Curve(),
		hash:                 cipherSuite.Hash(),
		participants:         participants,
		threshold:            uint(t),
		totalParties:         uint(participants.Size()),
		signatureAggregators: hashset.NewHashableHashSet(signatureAggregators...),
	}
	if err := types.ValidateThresholdSignatureProtocolConfig(tsig); err != nil {
		return nil, errs.WrapValidation(err, "tsig")
	}
	return tsig, nil
}

func MakeTranscripts(label string, identities []types.IdentityKey) (allTranscripts []transcripts.Transcript) {
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
