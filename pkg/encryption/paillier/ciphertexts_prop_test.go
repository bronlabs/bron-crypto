package paillier_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
)

const keyLen = 2048

// plaintextGenerator creates a generator for plaintexts in [-n/2, n/2).
func plaintextGenerator(ps *paillier.PlaintextSpace) *rapid.Generator[*paillier.Plaintext] {
	return rapid.Custom(func(t *rapid.T) *paillier.Plaintext {
		// Generate a small integer for testing
		val := rapid.Int64Range(-1_000_000, 1_000_000).Draw(t, "val")
		var n numct.Int
		if val >= 0 {
			n.SetNat(numct.NewNat(uint64(val)))
		} else {
			n.SetNat(numct.NewNat(uint64(-val)))
			n.Neg(&n)
		}
		pt, err := ps.FromInt(&n)
		if err != nil {
			t.Fatalf("failed to create plaintext: %v", err)
		}
		return pt
	})
}

// smallNatGenerator creates a generator for small natural numbers for scalar multiplication.
func smallNatGenerator() *rapid.Generator[*num.Nat] {
	return rapid.Custom(func(t *rapid.T) *num.Nat {
		val := rapid.Uint64Range(0, 1000).Draw(t, "scalar")
		return num.N().FromUint64(val)
	})
}

// --- Property Tests for Homomorphic Addition ---

func TestCiphertext_HomAdd_Commutativity_Property(t *testing.T) {
	t.Parallel()

	scheme := paillier.NewScheme()
	kg, err := scheme.Keygen(paillier.WithKeyLen(keyLen))
	require.NoError(t, err)
	sk, pk, err := kg.Generate(pcg.NewRandomised())
	require.NoError(t, err)
	enc, err := scheme.Encrypter()
	require.NoError(t, err)
	dec, err := scheme.Decrypter(sk)
	require.NoError(t, err)
	ps := pk.PlaintextSpace()
	ptGen := plaintextGenerator(ps)

	rapid.Check(t, func(rt *rapid.T) {
		pt1 := ptGen.Draw(rt, "pt1")
		pt2 := ptGen.Draw(rt, "pt2")

		ct1, _, err := enc.Encrypt(pt1, pk, crand.Reader)
		require.NoError(t, err)
		ct2, _, err := enc.Encrypt(pt2, pk, crand.Reader)
		require.NoError(t, err)

		sum1 := ct1.HomAdd(ct2)
		sum2 := ct2.HomAdd(ct1)

		dec1, err := dec.Decrypt(sum1)
		require.NoError(t, err)
		dec2, err := dec.Decrypt(sum2)
		require.NoError(t, err)

		require.True(t, dec1.Equal(dec2), "HomAdd should be commutative")
	})
}

func TestCiphertext_HomAdd_Associativity_Property(t *testing.T) {
	t.Parallel()

	scheme := paillier.NewScheme()
	kg, err := scheme.Keygen(paillier.WithKeyLen(keyLen))
	require.NoError(t, err)
	sk, pk, err := kg.Generate(pcg.NewRandomised())
	require.NoError(t, err)
	enc, err := scheme.Encrypter()
	require.NoError(t, err)
	dec, err := scheme.Decrypter(sk)
	require.NoError(t, err)
	ps := pk.PlaintextSpace()
	ptGen := plaintextGenerator(ps)

	rapid.Check(t, func(rt *rapid.T) {
		pt1 := ptGen.Draw(rt, "pt1")
		pt2 := ptGen.Draw(rt, "pt2")
		pt3 := ptGen.Draw(rt, "pt3")

		ct1, _, err := enc.Encrypt(pt1, pk, crand.Reader)
		require.NoError(t, err)
		ct2, _, err := enc.Encrypt(pt2, pk, crand.Reader)
		require.NoError(t, err)
		ct3, _, err := enc.Encrypt(pt3, pk, crand.Reader)
		require.NoError(t, err)

		// (ct1 + ct2) + ct3
		left := ct1.HomAdd(ct2).HomAdd(ct3)
		// ct1 + (ct2 + ct3)
		right := ct1.HomAdd(ct2.HomAdd(ct3))

		decLeft, err := dec.Decrypt(left)
		require.NoError(t, err)
		decRight, err := dec.Decrypt(right)
		require.NoError(t, err)

		require.True(t, decLeft.Equal(decRight), "HomAdd should be associative")
	})
}

func TestCiphertext_HomAdd_Identity_Property(t *testing.T) {
	t.Parallel()

	scheme := paillier.NewScheme()
	kg, err := scheme.Keygen(paillier.WithKeyLen(keyLen))
	require.NoError(t, err)
	sk, pk, err := kg.Generate(pcg.NewRandomised())
	require.NoError(t, err)
	enc, err := scheme.Encrypter()
	require.NoError(t, err)
	dec, err := scheme.Decrypter(sk)
	require.NoError(t, err)
	ps := pk.PlaintextSpace()
	ptGen := plaintextGenerator(ps)

	rapid.Check(t, func(rt *rapid.T) {
		pt := ptGen.Draw(rt, "pt")
		zero := ps.Zero()

		ct, _, err := enc.Encrypt(pt, pk, crand.Reader)
		require.NoError(t, err)
		ctZero, _, err := enc.Encrypt(zero, pk, crand.Reader)
		require.NoError(t, err)

		sum := ct.HomAdd(ctZero)

		decSum, err := dec.Decrypt(sum)
		require.NoError(t, err)

		require.True(t, pt.Equal(decSum), "x + 0 should equal x")
	})
}

func TestCiphertext_HomSub_Inverse_Property(t *testing.T) {
	t.Parallel()

	scheme := paillier.NewScheme()
	kg, err := scheme.Keygen(paillier.WithKeyLen(keyLen))
	require.NoError(t, err)
	sk, pk, err := kg.Generate(pcg.NewRandomised())
	require.NoError(t, err)
	enc, err := scheme.Encrypter()
	require.NoError(t, err)
	dec, err := scheme.Decrypter(sk)
	require.NoError(t, err)
	ps := pk.PlaintextSpace()
	ptGen := plaintextGenerator(ps)

	rapid.Check(t, func(rt *rapid.T) {
		pt := ptGen.Draw(rt, "pt")

		ct, _, err := enc.Encrypt(pt, pk, crand.Reader)
		require.NoError(t, err)

		// x - x should equal 0
		diff := ct.HomSub(ct)

		decDiff, err := dec.Decrypt(diff)
		require.NoError(t, err)

		require.True(t, ps.Zero().Equal(decDiff), "x - x should equal 0")
	})
}

// --- Property Tests for Scalar Multiplication ---

func TestCiphertext_ScalarMul_Zero_Property(t *testing.T) {
	t.Parallel()

	scheme := paillier.NewScheme()
	kg, err := scheme.Keygen(paillier.WithKeyLen(keyLen))
	require.NoError(t, err)
	sk, pk, err := kg.Generate(pcg.NewRandomised())
	require.NoError(t, err)
	enc, err := scheme.Encrypter()
	require.NoError(t, err)
	dec, err := scheme.Decrypter(sk)
	require.NoError(t, err)
	ps := pk.PlaintextSpace()
	ptGen := plaintextGenerator(ps)

	rapid.Check(t, func(rt *rapid.T) {
		pt := ptGen.Draw(rt, "pt")

		ct, _, err := enc.Encrypt(pt, pk, crand.Reader)
		require.NoError(t, err)

		// x * 0 should equal 0
		zero := num.N().FromUint64(0)
		ctMul := ct.ScalarMul(zero)

		decMul, err := dec.Decrypt(ctMul)
		require.NoError(t, err)

		require.True(t, ps.Zero().Equal(decMul), "x * 0 should equal 0")
	})
}

func TestCiphertext_ScalarMul_One_Property(t *testing.T) {
	t.Parallel()

	scheme := paillier.NewScheme()
	kg, err := scheme.Keygen(paillier.WithKeyLen(keyLen))
	require.NoError(t, err)
	sk, pk, err := kg.Generate(pcg.NewRandomised())
	require.NoError(t, err)
	enc, err := scheme.Encrypter()
	require.NoError(t, err)
	dec, err := scheme.Decrypter(sk)
	require.NoError(t, err)
	ps := pk.PlaintextSpace()
	ptGen := plaintextGenerator(ps)

	rapid.Check(t, func(rt *rapid.T) {
		pt := ptGen.Draw(rt, "pt")

		ct, _, err := enc.Encrypt(pt, pk, crand.Reader)
		require.NoError(t, err)

		// x * 1 should equal x
		one := num.N().FromUint64(1)
		ctMul := ct.ScalarMul(one)

		decMul, err := dec.Decrypt(ctMul)
		require.NoError(t, err)

		require.True(t, pt.Equal(decMul), "x * 1 should equal x")
	})
}

func TestCiphertext_ScalarMul_Distributive_Property(t *testing.T) {
	t.Parallel()

	scheme := paillier.NewScheme()
	kg, err := scheme.Keygen(paillier.WithKeyLen(keyLen))
	require.NoError(t, err)
	sk, pk, err := kg.Generate(pcg.NewRandomised())
	require.NoError(t, err)
	enc, err := scheme.Encrypter()
	require.NoError(t, err)
	dec, err := scheme.Decrypter(sk)
	require.NoError(t, err)
	ps := pk.PlaintextSpace()
	ptGen := plaintextGenerator(ps)
	scalarGen := smallNatGenerator()

	rapid.Check(t, func(rt *rapid.T) {
		pt1 := ptGen.Draw(rt, "pt1")
		pt2 := ptGen.Draw(rt, "pt2")
		k := scalarGen.Draw(rt, "k")

		ct1, _, err := enc.Encrypt(pt1, pk, crand.Reader)
		require.NoError(t, err)
		ct2, _, err := enc.Encrypt(pt2, pk, crand.Reader)
		require.NoError(t, err)

		// k * (ct1 + ct2)
		sum := ct1.HomAdd(ct2)
		left := sum.ScalarMul(k)

		// k * ct1 + k * ct2
		kCt1 := ct1.ScalarMul(k)
		kCt2 := ct2.ScalarMul(k)
		right := kCt1.HomAdd(kCt2)

		decLeft, err := dec.Decrypt(left)
		require.NoError(t, err)
		decRight, err := dec.Decrypt(right)
		require.NoError(t, err)

		require.True(t, decLeft.Equal(decRight), "k*(x+y) should equal k*x + k*y")
	})
}

// --- Property Tests for Encryption/Decryption Round-Trip ---

func TestEncryptDecrypt_RoundTrip_Property(t *testing.T) {
	t.Parallel()

	scheme := paillier.NewScheme()
	kg, err := scheme.Keygen(paillier.WithKeyLen(keyLen))
	require.NoError(t, err)
	sk, pk, err := kg.Generate(pcg.NewRandomised())
	require.NoError(t, err)
	enc, err := scheme.Encrypter()
	require.NoError(t, err)
	dec, err := scheme.Decrypter(sk)
	require.NoError(t, err)
	ps := pk.PlaintextSpace()
	ptGen := plaintextGenerator(ps)

	rapid.Check(t, func(rt *rapid.T) {
		pt := ptGen.Draw(rt, "pt")

		ct, _, err := enc.Encrypt(pt, pk, crand.Reader)
		require.NoError(t, err)

		decrypted, err := dec.Decrypt(ct)
		require.NoError(t, err)

		require.True(t, pt.Equal(decrypted), "decryption should recover original plaintext")
	})
}

func TestSelfEncryptDecrypt_RoundTrip_Property(t *testing.T) {
	t.Parallel()

	scheme := paillier.NewScheme()
	kg, err := scheme.Keygen(paillier.WithKeyLen(keyLen))
	require.NoError(t, err)
	sk, _, err := kg.Generate(pcg.NewRandomised())
	require.NoError(t, err)
	se, err := scheme.SelfEncrypter(sk)
	require.NoError(t, err)
	dec, err := scheme.Decrypter(sk)
	require.NoError(t, err)
	ps := sk.PublicKey().PlaintextSpace()
	ptGen := plaintextGenerator(ps)

	rapid.Check(t, func(rt *rapid.T) {
		pt := ptGen.Draw(rt, "pt")

		ct, _, err := se.SelfEncrypt(pt, crand.Reader)
		require.NoError(t, err)

		decrypted, err := dec.Decrypt(ct)
		require.NoError(t, err)

		require.True(t, pt.Equal(decrypted), "decryption should recover original plaintext")
	})
}

// --- Property Tests for Re-randomization ---

func TestCiphertext_ReRandomise_PreservesPlaintext_Property(t *testing.T) {
	t.Parallel()

	scheme := paillier.NewScheme()
	kg, err := scheme.Keygen(paillier.WithKeyLen(keyLen))
	require.NoError(t, err)
	sk, pk, err := kg.Generate(pcg.NewRandomised())
	require.NoError(t, err)
	enc, err := scheme.Encrypter()
	require.NoError(t, err)
	dec, err := scheme.Decrypter(sk)
	require.NoError(t, err)
	ps := pk.PlaintextSpace()
	ptGen := plaintextGenerator(ps)

	rapid.Check(t, func(rt *rapid.T) {
		pt := ptGen.Draw(rt, "pt")

		ct, _, err := enc.Encrypt(pt, pk, crand.Reader)
		require.NoError(t, err)

		ctRand, _, err := ct.ReRandomise(pk, crand.Reader)
		require.NoError(t, err)

		decOriginal, err := dec.Decrypt(ct)
		require.NoError(t, err)
		decRand, err := dec.Decrypt(ctRand)
		require.NoError(t, err)

		require.True(t, decOriginal.Equal(decRand), "re-randomization should preserve plaintext")
	})
}

// --- Property Tests for Homomorphism Correctness ---

func TestCiphertext_HomAdd_MatchesPlaintextAdd_Property(t *testing.T) {
	t.Parallel()

	scheme := paillier.NewScheme()
	kg, err := scheme.Keygen(paillier.WithKeyLen(keyLen))
	require.NoError(t, err)
	sk, pk, err := kg.Generate(pcg.NewRandomised())
	require.NoError(t, err)
	enc, err := scheme.Encrypter()
	require.NoError(t, err)
	dec, err := scheme.Decrypter(sk)
	require.NoError(t, err)
	ps := pk.PlaintextSpace()
	ptGen := plaintextGenerator(ps)

	rapid.Check(t, func(rt *rapid.T) {
		pt1 := ptGen.Draw(rt, "pt1")
		pt2 := ptGen.Draw(rt, "pt2")

		// Plaintext addition
		expectedSum := pt1.Add(pt2)

		// Homomorphic addition
		ct1, _, err := enc.Encrypt(pt1, pk, crand.Reader)
		require.NoError(t, err)
		ct2, _, err := enc.Encrypt(pt2, pk, crand.Reader)
		require.NoError(t, err)

		ctSum := ct1.HomAdd(ct2)
		decSum, err := dec.Decrypt(ctSum)
		require.NoError(t, err)

		require.True(t, expectedSum.Equal(decSum), "Dec(Enc(a) + Enc(b)) should equal a + b")
	})
}

func TestCiphertext_HomSub_MatchesPlaintextSub_Property(t *testing.T) {
	t.Parallel()

	scheme := paillier.NewScheme()
	kg, err := scheme.Keygen(paillier.WithKeyLen(keyLen))
	require.NoError(t, err)
	sk, pk, err := kg.Generate(pcg.NewRandomised())
	require.NoError(t, err)
	enc, err := scheme.Encrypter()
	require.NoError(t, err)
	dec, err := scheme.Decrypter(sk)
	require.NoError(t, err)
	ps := pk.PlaintextSpace()
	ptGen := plaintextGenerator(ps)

	rapid.Check(t, func(rt *rapid.T) {
		pt1 := ptGen.Draw(rt, "pt1")
		pt2 := ptGen.Draw(rt, "pt2")

		// Plaintext subtraction
		expectedDiff := pt1.Sub(pt2)

		// Homomorphic subtraction
		ct1, _, err := enc.Encrypt(pt1, pk, crand.Reader)
		require.NoError(t, err)
		ct2, _, err := enc.Encrypt(pt2, pk, crand.Reader)
		require.NoError(t, err)

		ctDiff := ct1.HomSub(ct2)
		decDiff, err := dec.Decrypt(ctDiff)
		require.NoError(t, err)

		require.True(t, expectedDiff.Equal(decDiff), "Dec(Enc(a) - Enc(b)) should equal a - b")
	})
}
