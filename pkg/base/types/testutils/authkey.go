package testutils

import (
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/stretchr/testify/require"
	"sort"
	"testing"
)

var _ types.AuthKey[*edwards25519.Point, *edwards25519.BaseFieldElement, *edwards25519.Scalar] = (*TestDeterministicAuthKey)(nil)
var _ types.IdentityKey[*edwards25519.Point, *edwards25519.BaseFieldElement, *edwards25519.Scalar] = (*TestDeterministicAuthKey)(nil)

type TestDeterministicAuthKey struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

func (k *TestDeterministicAuthKey) PublicKey() *edwards25519.Point {
	result, err := edwards25519.NewCurve().FromAffineCompressed(k.publicKey)
	if err != nil {
		panic(err)
	}
	return result
}

func (k *TestDeterministicAuthKey) HashCode() uint64 {
	return binary.BigEndian.Uint64(k.PublicKey().ToAffineCompressed())
}

func (k *TestDeterministicAuthKey) Equal(rhs types.IdentityKey[*edwards25519.Point, *edwards25519.BaseFieldElement, *edwards25519.Scalar]) bool {
	return subtle.ConstantTimeCompare(k.PublicKey().ToAffineCompressed(), rhs.PublicKey().ToAffineCompressed()) == 1
}

func (k *TestDeterministicAuthKey) String() string {
	return fmt.Sprintf("%x", k.PublicKey().ToAffineCompressed())
}

func (k *TestDeterministicAuthKey) Sign(message []byte) ([]byte, error) {
	signature, err := k.privateKey.Sign(crand.Reader, message, &ed25519.Options{})
	if err != nil {
		return nil, errs.WrapFailed(err, "could not sign message")
	}
	return signature, nil
}

func (k *TestDeterministicAuthKey) Verify(signature, message []byte) error {
	if ok := ed25519.Verify(k.PublicKey().ToAffineCompressed(), message, signature); !ok {
		return errs.NewFailed("invalid signature")
	}
	return nil
}

func (k *TestDeterministicAuthKey) Encrypt(plaintext []byte, opts any) ([]byte, error) {
	panic("not implemented")
}

func (k *TestDeterministicAuthKey) EncryptFrom(sender types.AuthKey[*edwards25519.Point, *edwards25519.BaseFieldElement, *edwards25519.Scalar], plaintext []byte, opts any) ([]byte, error) {
	panic("not implemented")
}

func (k *TestDeterministicAuthKey) Decrypt(ciphertext []byte) ([]byte, error) {
	panic("not implemented")
}

func (k *TestDeterministicAuthKey) DecryptFrom(sender types.IdentityKey[*edwards25519.Point, *edwards25519.BaseFieldElement, *edwards25519.Scalar], ciphertext []byte) ([]byte, error) {
	panic("not implemented")
}

func MakeTestIdentity(tb testing.TB) types.IdentityKey[*edwards25519.Point, *edwards25519.BaseFieldElement, *edwards25519.Scalar] {
	tb.Helper()

	pk, sk, err := ed25519.GenerateKey(crand.Reader)
	require.NoError(tb, err)

	return &TestDeterministicAuthKey{
		privateKey: sk,
		publicKey:  pk,
	}
}

func MakeTestIdentities(tb testing.TB, n int) []types.IdentityKey[*edwards25519.Point, *edwards25519.BaseFieldElement, *edwards25519.Scalar] {
	tb.Helper()

	if n <= 0 {
		tb.Fail()
	}

	identities := make([]types.IdentityKey[*edwards25519.Point, *edwards25519.BaseFieldElement, *edwards25519.Scalar], n)
	for i := 0; i < len(identities); i++ {
		identities[i] = MakeTestIdentity(tb)
	}

	sortedIdentities := types.ByPublicKey[*edwards25519.Point, *edwards25519.BaseFieldElement, *edwards25519.Scalar](identities)
	sort.Sort(sortedIdentities)
	return identities
}
