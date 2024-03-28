package testutils

import (
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"slices"
	"sort"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr"
	vanillaSchnorr "github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr/vanilla"
)

type TestAuthKey struct {
	suite      types.SigningSuite
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

/*.--------------------------------------------------------------------------.*/
/*.--------------------------------------------------------------------------.*/

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

/*.----------------------------- Deterministic ------------------------------.*/

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
