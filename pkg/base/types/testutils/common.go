package testutils

import (
	"bytes"
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"reflect"
	"slices"
	"sort"
	"strings"

	"github.com/bronlabs/krypton-primitives/pkg/encryptions/hpke"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/krypton-primitives/pkg/base"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/edwards25519"
	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	"github.com/bronlabs/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	"github.com/bronlabs/krypton-primitives/pkg/signatures/schnorr"
	vanillaSchnorr "github.com/bronlabs/krypton-primitives/pkg/signatures/schnorr/vanilla"
	"github.com/bronlabs/krypton-primitives/pkg/transcripts"
	"github.com/bronlabs/krypton-primitives/pkg/transcripts/hagrid"
)

type message struct {
	EphemeralPublicKey curves.Point
	CipherText         []byte
	AdditionalData     []byte
}

type TestAuthKey struct {
	suite      types.SigningSuite
	privateKey *vanillaSchnorr.PrivateKey
	publicKey  *vanillaSchnorr.PublicKey

	_ ds.Incomparable
}

type TestEncOptions struct {
	AdditionalData []byte
}

type TestIdentityKey = TestAuthKey

var (
	_           types.IdentityKey = (*TestAuthKey)(nil)
	_           types.AuthKey     = (*TestAuthKey)(nil)
	cipherSuite                   = &hpke.CipherSuite{
		KDF:  hpke.KDF_HKDF_SHA256,
		KEM:  hpke.DHKEM_P256_HKDF_SHA256,
		AEAD: hpke.AEAD_CHACHA_20_POLY_1305,
	}
)

func (k *TestAuthKey) PublicKey() curves.Point {
	return k.publicKey.A
}

func (k *TestAuthKey) HashCode() uint64 {
	return binary.BigEndian.Uint64(k.PublicKey().ToAffineCompressed())
}

func (k *TestAuthKey) Equal(rhs types.IdentityKey) bool {
	return subtle.ConstantTimeCompare(k.PublicKey().ToAffineCompressed(), rhs.PublicKey().ToAffineCompressed()) == 1
}

func (k *TestAuthKey) Sign(message []byte) ([]byte, error) {
	signer, err := vanillaSchnorr.NewSigner(k.suite, k.privateKey)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create schnorr signer")
	}
	signature, err := signer.Sign(message, crand.Reader)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not sign message")
	}
	return slices.Concat(signature.R.ToAffineCompressed(), signature.S.Bytes()), nil
}

func (k *TestAuthKey) Verify(signature, message []byte) error {
	r := k.suite.Curve().AdditiveIdentity()
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

	schnorrSignature := schnorr.NewSignature(vanillaSchnorr.NewEdDsaCompatibleVariant(), nil, r, s)
	schnorrPublicKey := &vanillaSchnorr.PublicKey{
		A: k.publicKey.A,
	}
	if err := vanillaSchnorr.Verify(k.suite, schnorrPublicKey, message, schnorrSignature); err != nil {
		return errs.WrapVerification(err, "could not verify schnorr signature")
	}
	return nil
}

func (k *TestAuthKey) Encrypt(plaintext []byte, opts any) ([]byte, error) {
	return encrypt(k.PublicKey(), plaintext, opts)
}

func (k *TestAuthKey) EncryptFrom(sender types.AuthKey, plaintext []byte, opts any) ([]byte, error) {
	senderKey, ok := sender.(*TestAuthKey)
	if !ok {
		return nil, errs.NewType("sender is not deterministic auth key")
	}

	return encryptFrom(&hpke.PrivateKey{PublicKey: k.PublicKey(), D: senderKey.privateKey.S}, plaintext, k.PublicKey(), opts)
}

func (k *TestAuthKey) Decrypt(ciphertext []byte) ([]byte, error) {
	return decrypt(&hpke.PrivateKey{PublicKey: k.PublicKey(), D: k.privateKey.S}, ciphertext)
}

func (k *TestAuthKey) DecryptFrom(sender types.IdentityKey, ciphertext []byte) ([]byte, error) {
	return decryptFrom(&hpke.PrivateKey{PublicKey: k.PublicKey(), D: k.privateKey.S}, ciphertext, sender)
}

func (k *TestAuthKey) String() string {
	return fmt.Sprintf("%x", k.PublicKey().ToAffineCompressed())
}

func (k *TestIdentityKey) MarshalJSON() ([]byte, error) {
	privateKey := k.privateKey.S.Bytes()
	publicKey := k.publicKey.A.ToAffineCompressed()
	return json.Marshal(&struct {
		PrivateKey []byte
		PublicKey  []byte
	}{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	})
}

func (k *TestIdentityKey) UnmarshalJSON(data []byte) error {
	var temp struct {
		PrivateKey []byte
		PublicKey  []byte
	}
	if err := json.Unmarshal(data, &temp); err != nil {
		return errs.WrapSerialisation(err, "could not unmarshal identity key")
	}
	A, err := edwards25519.NewCurve().Point().FromAffineCompressed(temp.PublicKey)
	if err != nil {
		return errs.WrapSerialisation(err, "could not unmarshal public key")
	}
	s, err := edwards25519.NewScalarField().Element().SetBytes(temp.PrivateKey)
	if err != nil {
		return errs.WrapSerialisation(err, "could not unmarshal private key")
	}
	privateKey := &vanillaSchnorr.PrivateKey{
		S: s,
		PublicKey: schnorr.PublicKey{
			A: A,
		},
	}
	k.privateKey = privateKey
	k.publicKey = &vanillaSchnorr.PublicKey{A: A}
	return nil
}

var _ types.AuthKey = (*TestDeterministicAuthKey)(nil)

type TestDeterministicAuthKey struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
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

func (k *TestDeterministicAuthKey) Sign(message []byte) ([]byte, error) {
	signature, err := k.privateKey.Sign(crand.Reader, message, &ed25519.Options{})
	if err != nil {
		return nil, errs.WrapFailed(err, "could not sign message")
	}
	return signature, nil
}

func (k *TestDeterministicAuthKey) Encrypt(plaintext []byte, opts any) ([]byte, error) {
	return encrypt(k.PublicKey(), plaintext, opts)
}

func (k *TestDeterministicAuthKey) EncryptFrom(sender types.AuthKey, plaintext []byte, opts any) ([]byte, error) {
	senderDeterministicKey, ok := sender.(*TestDeterministicAuthKey)
	if !ok {
		return nil, errs.NewType("sender is not deterministic auth key")
	}

	hashed := sha512.Sum512(senderDeterministicKey.privateKey.Seed())
	result, _ := edwards25519.NewScalar(0).SetBytesWithClampingLE(hashed[:32])

	return encryptFrom(&hpke.PrivateKey{PublicKey: k.PublicKey(), D: result}, plaintext, k.PublicKey(), opts)
}

func (k *TestDeterministicAuthKey) Decrypt(ciphertext []byte) ([]byte, error) {
	hashed := sha512.Sum512(k.privateKey.Seed())
	result, _ := edwards25519.NewScalar(0).SetBytesWithClampingLE(hashed[:32])

	return decrypt(&hpke.PrivateKey{PublicKey: k.PublicKey(), D: result}, ciphertext)
}

func (k *TestDeterministicAuthKey) DecryptFrom(sender types.IdentityKey, ciphertext []byte) ([]byte, error) {
	hashed := sha512.Sum512(k.privateKey.Seed())
	result, _ := edwards25519.NewScalar(0).SetBytesWithClampingLE(hashed[:32])

	return decryptFrom(&hpke.PrivateKey{PublicKey: k.PublicKey(), D: result}, ciphertext, sender)
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

func encrypt(publicKey curves.Point, plaintext []byte, opts any) ([]byte, error) {
	var additionalData []byte
	options, ok := opts.(*TestEncOptions)
	if ok {
		additionalData = options.AdditionalData
	}

	cipherText, ephemeralPublicKey, err := hpke.Seal(hpke.Base, cipherSuite, plaintext, additionalData, publicKey, nil, nil, nil, nil, crand.Reader)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not encrypt message")
	}
	msg := &message{
		EphemeralPublicKey: ephemeralPublicKey,
		CipherText:         cipherText,
		AdditionalData:     additionalData,
	}
	encryptedPayload := new(bytes.Buffer)
	enc := gob.NewEncoder(encryptedPayload)
	err = enc.Encode(msg)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not encode message")
	}

	return encryptedPayload.Bytes(), nil
}

func encryptFrom(key *hpke.PrivateKey, plaintext []byte, receiverKey curves.Point, opts any) ([]byte, error) {
	var additionalData []byte
	if opts != nil {
		options, ok := opts.(*TestEncOptions)
		if ok {
			additionalData = options.AdditionalData
		}
	}

	cipherText, ephemeralPublicKey, err := hpke.Seal(hpke.Auth, cipherSuite, plaintext, additionalData, receiverKey, key, nil, nil, nil, crand.Reader)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not encrypt message")
	}
	msg := &message{
		EphemeralPublicKey: ephemeralPublicKey,
		CipherText:         cipherText,
		AdditionalData:     additionalData,
	}
	encryptedPayload := new(bytes.Buffer)
	enc := gob.NewEncoder(encryptedPayload)
	err = enc.Encode(msg)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not encode message")
	}

	return encryptedPayload.Bytes(), nil
}

func decrypt(key *hpke.PrivateKey, ciphertext []byte) ([]byte, error) {
	dec := gob.NewDecoder(bytes.NewReader(ciphertext))
	msg := &message{}
	if err := dec.Decode(msg); err != nil {
		return nil, errs.WrapSerialisation(err, "could not decode message")
	}

	decrypted, err := hpke.Open(hpke.Base, cipherSuite, msg.CipherText, msg.AdditionalData, key, msg.EphemeralPublicKey, nil, nil, nil, nil)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not decrypt message")
	}

	return decrypted, nil
}

func decryptFrom(key *hpke.PrivateKey, ciphertext []byte, senderKey types.IdentityKey) ([]byte, error) {
	dec := gob.NewDecoder(bytes.NewReader(ciphertext))
	msg := &message{}
	if err := dec.Decode(msg); err != nil {
		return nil, errs.WrapSerialisation(err, "could not decode message")
	}

	decrypted, err := hpke.Open(hpke.Auth, cipherSuite, msg.CipherText, msg.AdditionalData, key, msg.EphemeralPublicKey, senderKey.PublicKey(), nil, nil, nil)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not decrypt message")
	}

	return decrypted, nil
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

func MakeTestIdentities(cipherSuite types.SigningSuite, n int) (identities []types.IdentityKey, err error) {
	if err := types.ValidateSigningSuite(cipherSuite); err != nil {
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

func MakeTestIdentity(cipherSuite types.SigningSuite, secret curves.Scalar) (types.IdentityKey, error) {
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

func MakeTestAuthKeys(cipherSuite types.SigningSuite, n int) (authKeys []types.AuthKey, err error) {
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

func MakeTestAuthKey(cipherSuite types.SigningSuite, secret curves.Scalar) (types.AuthKey, error) {
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

var _ types.SigningSuite = (*CipherSuite)(nil)

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
	flags                ds.Set[types.ValidationFlag]
	threshold            uint
	totalParties         uint
	signatureAggregators ds.Set[types.IdentityKey]
	presignatureComposer types.IdentityKey
}

func (p *Protocol) Clone() types.Protocol {
	var clonedSignatureAggregators ds.Set[types.IdentityKey]
	if p.signatureAggregators != nil {
		clonedSignatureAggregators = p.signatureAggregators.Clone()
	}
	var clonedFlags ds.Set[types.ValidationFlag]
	if p.flags != nil {
		clonedFlags = p.flags.Clone()
	}
	var clonedParticipants ds.Set[types.IdentityKey]
	if p.participants != nil {
		clonedParticipants = p.participants.Clone()
	}
	return &Protocol{
		curve:                p.curve,
		hash:                 p.hash,
		participants:         clonedParticipants,
		flags:                clonedFlags,
		threshold:            p.threshold,
		totalParties:         p.totalParties,
		signatureAggregators: clonedSignatureAggregators,
		presignatureComposer: p.presignatureComposer,
	}
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

func (p *Protocol) SigningSuite() types.SigningSuite {
	return &CipherSuite{
		curve: p.curve,
		hash:  p.hash,
	}
}

func (*Protocol) MarshalJSON() ([]byte, error) {
	panic("not implemented")
}

func (p *Protocol) Flags() ds.Set[types.ValidationFlag] {
	if p.flags == nil {
		p.flags = hashset.NewComparableHashSet[types.ValidationFlag]()
	}
	return p.flags
}

func MakeProtocol(curve curves.Curve, identities []types.IdentityKey) (types.Protocol, error) {
	protocol := &Protocol{
		curve:        curve,
		participants: hashset.NewHashableHashSet(identities...),
	}
	if err := types.ValidateProtocolConfig(protocol); err != nil {
		return nil, errs.WrapValidation(err, "protocol")
	}
	return protocol, nil
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

func MakeSigningSuite(curve curves.Curve, h func() hash.Hash) (types.SigningSuite, error) {
	sig := &Protocol{
		curve: curve,
		hash:  h,
	}
	if err := types.ValidateSigningSuite(sig); err != nil {
		return nil, errs.WrapValidation(err, "sig")
	}
	return sig, nil
}

func MakeThresholdSignatureProtocol(cipherSuite types.SigningSuite, identities []types.IdentityKey, t int, signatureAggregators []types.IdentityKey) (types.ThresholdSignatureProtocol, error) {
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

func GobRoundTrip[M any](t require.TestingT, message M) M {
	if reflect.ValueOf(message).IsNil() {
		return message
	}

	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(message)
	require.NoError(t, err)
	dec := gob.NewDecoder(&buf)
	var out M
	err = dec.Decode(&out)
	require.NoError(t, err)
	return out
}
