package testutils

import (
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/stretchr/testify/require"
	"hash/fnv"
	"sort"
	"testing"
)

var _ types.AuthKey = (*TestDeterministicAuthKey)(nil)
var _ types.IdentityKey = (*TestDeterministicAuthKey)(nil)

type TestDeterministicAuthKey struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

func (k *TestDeterministicAuthKey) PublicKeyBytes() []byte {
	return k.publicKey
}

func (k *TestDeterministicAuthKey) HashCode() uint64 {
	h := fnv.New64a()
	_, _ = h.Write(k.publicKey)
	return h.Sum64()
}

func (k *TestDeterministicAuthKey) Equal(rhs types.IdentityKey) bool {
	return subtle.ConstantTimeCompare(k.PublicKeyBytes(), rhs.PublicKeyBytes()) != 0
}

func (k *TestDeterministicAuthKey) String() string {
	return hex.EncodeToString(k.publicKey)
}

func (k *TestDeterministicAuthKey) Sign(message []byte) ([]byte, error) {
	signature, err := k.privateKey.Sign(crand.Reader, message, &ed25519.Options{})
	if err != nil {
		return nil, errs.WrapFailed(err, "could not sign message")
	}
	return signature, nil
}

func (k *TestDeterministicAuthKey) Verify(signature, message []byte) error {
	if ok := ed25519.Verify(k.publicKey, message, signature); !ok {
		return errs.NewFailed("invalid signature")
	}
	return nil
}

func (k *TestDeterministicAuthKey) Encrypt(plaintext []byte, opts any) ([]byte, error) {
	panic("not implemented")
}

func (k *TestDeterministicAuthKey) EncryptFrom(sender types.AuthKey, plaintext []byte, opts any) ([]byte, error) {
	panic("not implemented")
}

func (k *TestDeterministicAuthKey) Decrypt(ciphertext []byte) ([]byte, error) {
	panic("not implemented")
}

func (k *TestDeterministicAuthKey) DecryptFrom(sender types.IdentityKey, ciphertext []byte) ([]byte, error) {
	panic("not implemented")
}

func MakeTestIdentity(tb testing.TB) types.IdentityKey {
	tb.Helper()

	pk, sk, err := ed25519.GenerateKey(crand.Reader)
	require.NoError(tb, err)

	return &TestDeterministicAuthKey{
		privateKey: sk,
		publicKey:  pk,
	}
}

func MakeTestIdentities(tb testing.TB, n uint) []types.IdentityKey {
	tb.Helper()

	if n <= 0 {
		tb.Fail()
	}

	identities := make([]types.IdentityKey, n)
	for i := 0; i < len(identities); i++ {
		identities[i] = MakeTestIdentity(tb)
	}

	sortedIdentities := types.ByPublicKey(identities)
	sort.Sort(sortedIdentities)
	return identities
}
