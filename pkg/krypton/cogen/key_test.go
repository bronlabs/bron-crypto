package cogen_test

import (
	"bytes"
	nativeEcdsa "crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"

	"github.com/cronokirby/saferith"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/ecdsa"
)

var curve = k256.NewCurve()
var hashFunc = sha3.NewLegacyKeccak256

func NewCogenAuthKey(prng io.Reader) (integration.AuthKey, error) {
	curve := k256.NewCurve()
	privateKey, err := curve.ScalarField().Random(prng)
	if err != nil {
		return nil, err
	}
	publicKey := curve.ScalarBaseMult(privateKey)
	return &TestAuthKey{
		publicKey:  publicKey,
		privateKey: privateKey,
	}, nil
}

func NewCogenIdentityKey(publicKey curves.Point) (integration.IdentityKey, error) {
	return &TestIdentityKey{
		publicKey: publicKey,
	}, nil
}

var _ integration.IdentityKey = (*TestIdentityKey)(nil)

type TestIdentityKey struct {
	publicKey curves.Point
}

// Hash implements integration.IdentityKey.
func (i *TestIdentityKey) Hash() [32]byte {
	return sha256.Sum256(i.publicKey.ToAffineCompressed())
}

// PublicKey implements integration.IdentityKey.
func (i *TestIdentityKey) PublicKey() curves.Point {
	return i.publicKey
}

// Verify implements integration.IdentityKey.
func (*TestIdentityKey) Verify(signature []byte, message []byte) error {
	return nil
}

var _ integration.AuthKey = (*TestAuthKey)(nil)

type TestAuthKey struct {
	publicKey  curves.Point
	privateKey curves.Scalar
}

// Hash implements integration.AuthKey.
func (a *TestAuthKey) Hash() [32]byte {
	return sha256.Sum256(a.publicKey.ToAffineCompressed())
}

// PrivateKey implements integration.AuthKey.
func (a *TestAuthKey) PrivateKey() curves.Scalar {
	return a.privateKey
}

// PublicKey implements integration.AuthKey.
func (a *TestAuthKey) PublicKey() curves.Point {
	return a.publicKey
}

// Sign implements integration.AuthKey.
func (a *TestAuthKey) Sign(message []byte) []byte {
	messageHash, err := hashing.Hash(hashFunc, message)
	if err != nil {
		panic(err)
	}
	nativePrivateKey := new(nativeEcdsa.PrivateKey)
	nativePrivateKey.PublicKey.Curve = elliptic.P256()
	nativePrivateKey.PublicKey.X = new(big.Int).SetBytes(a.publicKey.AffineX().Bytes())
	nativePrivateKey.PublicKey.Y = new(big.Int).SetBytes(a.publicKey.AffineY().Bytes())
	nativePrivateKey.D = new(big.Int).SetBytes(a.privateKey.Bytes())
	nativeR, nativeS, err := nativeEcdsa.Sign(crand.Reader, nativePrivateKey, messageHash)
	if err != nil {
		panic(err)
	}
	r, err := curve.Scalar().SetBytes(nativeR.Bytes())
	if err != nil {
		panic(err)
	}
	s, err := curve.Scalar().SetBytes(nativeS.Bytes())
	if err != nil {
		panic(err)
	}
	var recoveryId byte
	for v := 0; v < 4; v++ {
		if err := ecdsa.Verify(&ecdsa.Signature{V: &v, R: r, S: s}, hashFunc, a.publicKey, message); err == nil {
			recoveryId = byte(v)
			break
		}
	}
	if err != nil {
		panic(err)
	}
	return bytes.Join([][]byte{r.Bytes(), s.Bytes(), {recoveryId}}, nil)
}

// Verify implements integration.AuthKey.
func (a *TestAuthKey) Verify(signature []byte, message []byte) error {
	messageHash, err := hashing.Hash(hashFunc, message)
	if err != nil {
		panic(err)
	}
	publicKey := new(nativeEcdsa.PublicKey)
	publicKey.Curve = elliptic.P256()
	publicKey.X = new(big.Int).SetBytes(a.publicKey.AffineX().Bytes())
	publicKey.Y = new(big.Int).SetBytes(a.publicKey.AffineY().Bytes())
	r := new(saferith.Nat).SetBytes(signature[:32])
	s := new(saferith.Nat).SetBytes(signature[32:64])
	bigR := r.Big()
	bigS := s.Big()
	ok := nativeEcdsa.Verify(publicKey, messageHash, bigR, bigS)
	if !ok {
		return fmt.Errorf("failed to verify signature")
	}
	return nil
}
