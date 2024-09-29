package testutils

import (
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr/vanilla"
	"hash/fnv"
	"strings"
)

var (
	_ types.IdentityKey = (*TestIdentityKey)(nil)
	_ types.AuthKey     = (*TestAuthKey)(nil)
)

type TestIdentityKey struct {
	pk curves.Point
}

func NewTestIdentityKey(pk curves.Point) *TestIdentityKey {
	if pk == nil || pk.Curve().Name() != p256.Name || pk.IsAdditiveIdentity() {
		panic("invalid public key")
	}

	return &TestIdentityKey{pk: pk}
}

func (k *TestIdentityKey) String() string {
	return strings.ToUpper(hex.EncodeToString(k.pk.ToAffineCompressed()))
}

func (k *TestIdentityKey) PublicKey() curves.Point {
	return k.pk
}

func (k *TestIdentityKey) Verify(signature []byte, message []byte) error {
	suite, err := types.NewSigningSuite(k.pk.Curve(), sha256.New)
	if err != nil {
		panic(err)
	}
	pk := &vanilla.PublicKey{A: k.pk}
	rBytes := signature[:33]
	sBytes := signature[33:]
	r, err := k.pk.Curve().Point().FromAffineCompressed(rBytes)
	if err != nil {
		return err
	}
	s, err := k.pk.Curve().ScalarField().Scalar().SetBytes(bitstring.ReverseBytes(sBytes[:]))
	if err != nil {
		return err
	}
	sig := schnorr.NewSignature(vanilla.NewEdDsaCompatibleVariant(), nil, r, s)
	return vanilla.Verify(suite, pk, message, sig)
}

func (k *TestIdentityKey) Equal(rhs types.IdentityKey) bool {
	return k.pk.Equal(rhs.PublicKey())
}

func (k *TestIdentityKey) HashCode() uint64 {
	h := fnv.New64a()
	_, err := h.Write(k.pk.ToAffineCompressed())
	if err != nil {
		panic(err)
	}
	return h.Sum64()
}

func (k *TestIdentityKey) MarshalJSON() ([]byte, error) {
	panic("implement me")
}

type TestAuthKey struct {
	sk curves.Scalar
}

func NewTestAuthKey(sk curves.Scalar) *TestAuthKey {
	if sk == nil || sk.ScalarField().Curve().Name() != p256.Name || sk.IsAdditiveIdentity() {
		panic("invalid secret key")
	}

	return &TestAuthKey{sk: sk}
}

func (k *TestAuthKey) String() string {
	return strings.ToUpper(hex.EncodeToString(k.sk.Bytes()))
}

func (k *TestAuthKey) PublicKey() curves.Point {
	return k.sk.ScalarField().Curve().ScalarBaseMult(k.sk)
}

func (k *TestAuthKey) Verify(signature []byte, message []byte) error {
	suite, err := types.NewSigningSuite(k.sk.ScalarField().Curve(), sha256.New)
	if err != nil {
		panic(err)
	}
	pk, _, err := vanilla.NewKeys(k.sk)
	if err != nil {
		panic(err)
	}
	rBytes := signature[:33]
	sBytes := signature[33:]
	r, err := k.sk.ScalarField().Curve().Point().FromAffineCompressed(rBytes)
	if err != nil {
		return err
	}
	s, err := k.sk.ScalarField().Scalar().SetBytes(bitstring.ReverseBytes(sBytes[:]))
	if err != nil {
		return err
	}
	sig := schnorr.NewSignature(vanilla.NewEdDsaCompatibleVariant(), nil, r, s)
	return vanilla.Verify(suite, pk, message, sig)
}

func (k *TestAuthKey) Equal(rhs types.IdentityKey) bool {
	return k.PublicKey().Equal(rhs.PublicKey())
}

func (k *TestAuthKey) HashCode() uint64 {
	h := fnv.New64a()
	_, err := h.Write(k.PublicKey().ToAffineCompressed())
	if err != nil {
		panic(err)
	}
	return h.Sum64()
}

func (k *TestAuthKey) MarshalJSON() ([]byte, error) {
	panic("implement me")
}

func (k *TestAuthKey) Sign(message []byte) []byte {
	suite, err := types.NewSigningSuite(k.sk.ScalarField().Curve(), sha256.New)
	if err != nil {
		panic(err)
	}
	_, schnorrSk, err := vanilla.NewKeys(k.sk)
	if err != nil {
		panic(err)
	}
	signer, err := vanilla.NewSigner(suite, schnorrSk)
	if err != nil {
		panic(err)
	}
	signature, err := signer.Sign(message, crand.Reader)
	if err != nil {
		panic(err)
	}
	sig, err := signature.MarshalBinary()
	if err != nil {
		panic(err)
	}

	return sig
}

func (k *TestAuthKey) PrivateKey() curves.Scalar {
	return k.sk
}
