package elgamal_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/krypton-primitives/pkg/indcpa/elgamal"
)

func Test_RoundTrip(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	sk, pk, err := elgamal.KeyGen(prng)
	require.NoError(t, err)

	m := new(saferith.Nat).SetUint64(0xdeadbeefcafebabe)
	plaintext, err := elgamal.NewPlaintext2048FromNat(m)
	require.NoError(t, err)

	c, _, err := pk.Encrypt(plaintext, prng)
	require.NoError(t, err)

	d, err := sk.Decrypt(c)
	require.NoError(t, err)

	m2 := d.ToNat()
	require.True(t, m2.Eq(m) == 1)
}

func Test_HomomorphicAdd(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	sk, pk, err := elgamal.KeyGen(prng)
	require.NoError(t, err)

	m1 := new(saferith.Nat).SetUint64(0xdeadbeefcafebabe)
	m2 := new(saferith.Nat).SetUint64(0x0badc0de00001234)
	m := new(saferith.Nat).Mul(m1, m2, 128)

	p1, err := elgamal.NewPlaintext2048FromNat(m1)
	require.NoError(t, err)
	p2, err := elgamal.NewPlaintext2048FromNat(m2)
	require.NoError(t, err)

	c1, r1, err := pk.Encrypt(p1, prng)
	require.NoError(t, err)
	c2, r2, err := pk.Encrypt(p2, prng)
	require.NoError(t, err)
	c, err := pk.CipherTextAdd(c1, c2)
	require.NoError(t, err)
	r, err := pk.NonceAdd(r1, r2)
	require.NoError(t, err)
	require.NotNil(t, r)

	// check decryption
	d, err := sk.Decrypt(c)
	require.NoError(t, err)
	p := d.ToNat()
	require.True(t, p.Eq(m) == 1)

	// check re-encryption
	pr, err := elgamal.NewPlaintext2048FromNat(m)
	require.NoError(t, err)
	cr, err := pk.EncryptWithNonce(pr, r)
	require.NoError(t, err)
	require.True(t, pk.CipherTextEqual(cr, c))
}

func Test_HomomorphicAddPlain(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	sk, pk, err := elgamal.KeyGen(prng)
	require.NoError(t, err)

	m1 := new(saferith.Nat).SetUint64(0xdeadbeefcafebabe)
	m2 := new(saferith.Nat).SetUint64(0x0badc0de00000000)
	m := new(saferith.Nat).Mul(m1, m2, 128)

	p1, err := elgamal.NewPlaintext2048FromNat(m1)
	require.NoError(t, err)
	p2, err := elgamal.NewPlaintext2048FromNat(m2)
	require.NoError(t, err)

	c1, r1, err := pk.Encrypt(p1, prng)
	require.NoError(t, err)
	c, err := pk.CipherTextAddPlainText(c1, p2)
	require.NoError(t, err)

	// check decryption
	d, err := sk.Decrypt(c)
	require.NoError(t, err)
	p := d.ToNat()
	require.True(t, p.Eq(m) == 1)

	// check re-encryption
	pr, err := elgamal.NewPlaintext2048FromNat(m)
	require.NoError(t, err)
	cr, err := pk.EncryptWithNonce(pr, r1)
	require.NoError(t, err)
	require.True(t, pk.CipherTextEqual(cr, c))
}

func Test_HomomorphicSub(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	sk, pk, err := elgamal.KeyGen(prng)
	require.NoError(t, err)

	m1 := new(saferith.Nat).SetUint64(1_000_000)
	m2 := new(saferith.Nat).SetUint64(10_000)
	m := new(saferith.Nat).SetUint64(100)

	p1, err := elgamal.NewPlaintext2048FromNat(m1)
	require.NoError(t, err)
	p2, err := elgamal.NewPlaintext2048FromNat(m2)
	require.NoError(t, err)

	c1, r1, err := pk.Encrypt(p1, prng)
	require.NoError(t, err)
	c2, r2, err := pk.Encrypt(p2, prng)
	require.NoError(t, err)
	c, err := pk.CipherTextSub(c1, c2)
	require.NoError(t, err)
	r, err := pk.NonceSub(r1, r2)
	require.NoError(t, err)
	require.NotNil(t, r)

	// check decryption
	d, err := sk.Decrypt(c)
	require.NoError(t, err)
	p := d.ToNat()
	require.True(t, p.Eq(m) == 1)

	// check re-encryption
	pr, err := elgamal.NewPlaintext2048FromNat(m)
	require.NoError(t, err)
	cr, err := pk.EncryptWithNonce(pr, r)
	require.NoError(t, err)
	require.True(t, pk.CipherTextEqual(cr, c))
}

func Test_HomomorphicSubPlain(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	sk, pk, err := elgamal.KeyGen(prng)
	require.NoError(t, err)

	m1 := new(saferith.Nat).SetUint64(1_000_000)
	m2 := new(saferith.Nat).SetUint64(10_000)
	m := new(saferith.Nat).SetUint64(100)

	p1, err := elgamal.NewPlaintext2048FromNat(m1)
	require.NoError(t, err)
	p2, err := elgamal.NewPlaintext2048FromNat(m2)
	require.NoError(t, err)

	c1, r1, err := pk.Encrypt(p1, prng)
	require.NoError(t, err)
	c, err := pk.CipherTextSubPlainText(c1, p2)
	require.NoError(t, err)

	// check decryption
	d, err := sk.Decrypt(c)
	require.NoError(t, err)
	p := d.ToNat()
	require.True(t, p.Eq(m) == 1)

	// check re-encryption
	pr, err := elgamal.NewPlaintext2048FromNat(m)
	require.NoError(t, err)
	cr, err := pk.EncryptWithNonce(pr, r1)
	require.NoError(t, err)
	require.True(t, pk.CipherTextEqual(cr, c))
}
