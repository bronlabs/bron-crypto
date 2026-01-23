package paillier_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
)

// --- Test Helpers ---

type ciphertextTestContext struct {
	scheme *paillier.Scheme
	sk     *paillier.PrivateKey
	pk     *paillier.PublicKey
	enc    *paillier.Encrypter
	dec    *paillier.Decrypter
	ps     *paillier.PlaintextSpace
}

func newCiphertextTestContext(tb testing.TB) *ciphertextTestContext {
	tb.Helper()
	scheme := paillier.NewScheme()
	kg, err := scheme.Keygen(paillier.WithKeyLen(keyLen))
	require.NoError(tb, err)
	sk, pk, err := kg.Generate(crand.Reader)
	require.NoError(tb, err)
	enc, err := scheme.Encrypter()
	require.NoError(tb, err)
	dec, err := scheme.Decrypter(sk)
	require.NoError(tb, err)
	return &ciphertextTestContext{
		scheme: scheme,
		sk:     sk,
		pk:     pk,
		enc:    enc,
		dec:    dec,
		ps:     pk.PlaintextSpace(),
	}
}

func (tc *ciphertextTestContext) plaintextFromInt64(tb testing.TB, val int64) *paillier.Plaintext {
	tb.Helper()
	var n numct.Int
	if val >= 0 {
		n.SetNat(numct.NewNat(uint64(val)))
	} else {
		n.SetNat(numct.NewNat(uint64(-val)))
		n.Neg(&n)
	}
	pt, err := tc.ps.FromInt(&n)
	require.NoError(tb, err)
	return pt
}

func (tc *ciphertextTestContext) encrypt(tb testing.TB, pt *paillier.Plaintext) *paillier.Ciphertext {
	tb.Helper()
	ct, _, err := tc.enc.Encrypt(pt, tc.pk, crand.Reader)
	require.NoError(tb, err)
	return ct
}

func (tc *ciphertextTestContext) decrypt(tb testing.TB, ct *paillier.Ciphertext) *paillier.Plaintext {
	tb.Helper()
	pt, err := tc.dec.Decrypt(ct)
	require.NoError(tb, err)
	return pt
}

// --- Homomorphic Addition Tests ---

func TestCiphertext_HomAdd_TwoPositive(t *testing.T) {
	t.Parallel()
	tc := newCiphertextTestContext(t)

	pt1 := tc.plaintextFromInt64(t, 100)
	pt2 := tc.plaintextFromInt64(t, 200)

	ct1 := tc.encrypt(t, pt1)
	ct2 := tc.encrypt(t, pt2)

	ctSum := ct1.HomAdd(ct2)
	decrypted := tc.decrypt(t, ctSum)

	expected := tc.plaintextFromInt64(t, 300)
	require.True(t, expected.Equal(decrypted), "100 + 200 should equal 300")
}

func TestCiphertext_HomAdd_PositiveAndNegative(t *testing.T) {
	t.Parallel()
	tc := newCiphertextTestContext(t)

	pt1 := tc.plaintextFromInt64(t, 500)
	pt2 := tc.plaintextFromInt64(t, -200)

	ct1 := tc.encrypt(t, pt1)
	ct2 := tc.encrypt(t, pt2)

	ctSum := ct1.HomAdd(ct2)
	decrypted := tc.decrypt(t, ctSum)

	expected := tc.plaintextFromInt64(t, 300)
	require.True(t, expected.Equal(decrypted), "500 + (-200) should equal 300")
}

func TestCiphertext_HomAdd_ResultNegative(t *testing.T) {
	t.Parallel()
	tc := newCiphertextTestContext(t)

	pt1 := tc.plaintextFromInt64(t, 100)
	pt2 := tc.plaintextFromInt64(t, -500)

	ct1 := tc.encrypt(t, pt1)
	ct2 := tc.encrypt(t, pt2)

	ctSum := ct1.HomAdd(ct2)
	decrypted := tc.decrypt(t, ctSum)

	expected := tc.plaintextFromInt64(t, -400)
	require.True(t, expected.Equal(decrypted), "100 + (-500) should equal -400")
}

func TestCiphertext_HomAdd_TwoNegative(t *testing.T) {
	t.Parallel()
	tc := newCiphertextTestContext(t)

	pt1 := tc.plaintextFromInt64(t, -100)
	pt2 := tc.plaintextFromInt64(t, -200)

	ct1 := tc.encrypt(t, pt1)
	ct2 := tc.encrypt(t, pt2)

	ctSum := ct1.HomAdd(ct2)
	decrypted := tc.decrypt(t, ctSum)

	expected := tc.plaintextFromInt64(t, -300)
	require.True(t, expected.Equal(decrypted), "-100 + (-200) should equal -300")
}

func TestCiphertext_HomAdd_WithZero(t *testing.T) {
	t.Parallel()
	tc := newCiphertextTestContext(t)

	pt1 := tc.plaintextFromInt64(t, 12345)
	pt2 := tc.ps.Zero()

	ct1 := tc.encrypt(t, pt1)
	ct2 := tc.encrypt(t, pt2)

	ctSum := ct1.HomAdd(ct2)
	decrypted := tc.decrypt(t, ctSum)

	require.True(t, pt1.Equal(decrypted), "x + 0 should equal x")
}

func TestCiphertext_HomAdd_Commutativity(t *testing.T) {
	t.Parallel()
	tc := newCiphertextTestContext(t)

	pt1 := tc.plaintextFromInt64(t, 123)
	pt2 := tc.plaintextFromInt64(t, 456)

	ct1 := tc.encrypt(t, pt1)
	ct2 := tc.encrypt(t, pt2)

	sum1 := ct1.HomAdd(ct2)
	sum2 := ct2.HomAdd(ct1)

	dec1 := tc.decrypt(t, sum1)
	dec2 := tc.decrypt(t, sum2)

	require.True(t, dec1.Equal(dec2), "HomAdd should be commutative")
}

func TestCiphertext_HomAdd_Associativity(t *testing.T) {
	t.Parallel()
	tc := newCiphertextTestContext(t)

	pt1 := tc.plaintextFromInt64(t, 100)
	pt2 := tc.plaintextFromInt64(t, 200)
	pt3 := tc.plaintextFromInt64(t, 300)

	ct1 := tc.encrypt(t, pt1)
	ct2 := tc.encrypt(t, pt2)
	ct3 := tc.encrypt(t, pt3)

	// (ct1 + ct2) + ct3
	left := ct1.HomAdd(ct2).HomAdd(ct3)
	// ct1 + (ct2 + ct3)
	right := ct1.HomAdd(ct2.HomAdd(ct3))

	decLeft := tc.decrypt(t, left)
	decRight := tc.decrypt(t, right)

	require.True(t, decLeft.Equal(decRight), "HomAdd should be associative")
	expected := tc.plaintextFromInt64(t, 600)
	require.True(t, expected.Equal(decLeft))
}

// --- Homomorphic Subtraction Tests ---

func TestCiphertext_HomSub_PositiveResult(t *testing.T) {
	t.Parallel()
	tc := newCiphertextTestContext(t)

	pt1 := tc.plaintextFromInt64(t, 500)
	pt2 := tc.plaintextFromInt64(t, 200)

	ct1 := tc.encrypt(t, pt1)
	ct2 := tc.encrypt(t, pt2)

	ctDiff := ct1.HomSub(ct2)
	decrypted := tc.decrypt(t, ctDiff)

	expected := tc.plaintextFromInt64(t, 300)
	require.True(t, expected.Equal(decrypted), "500 - 200 should equal 300")
}

func TestCiphertext_HomSub_NegativeResult(t *testing.T) {
	t.Parallel()
	tc := newCiphertextTestContext(t)

	pt1 := tc.plaintextFromInt64(t, 100)
	pt2 := tc.plaintextFromInt64(t, 500)

	ct1 := tc.encrypt(t, pt1)
	ct2 := tc.encrypt(t, pt2)

	ctDiff := ct1.HomSub(ct2)
	decrypted := tc.decrypt(t, ctDiff)

	expected := tc.plaintextFromInt64(t, -400)
	require.True(t, expected.Equal(decrypted), "100 - 500 should equal -400")
}

func TestCiphertext_HomSub_SubtractNegative(t *testing.T) {
	t.Parallel()
	tc := newCiphertextTestContext(t)

	pt1 := tc.plaintextFromInt64(t, 100)
	pt2 := tc.plaintextFromInt64(t, -200)

	ct1 := tc.encrypt(t, pt1)
	ct2 := tc.encrypt(t, pt2)

	ctDiff := ct1.HomSub(ct2)
	decrypted := tc.decrypt(t, ctDiff)

	expected := tc.plaintextFromInt64(t, 300)
	require.True(t, expected.Equal(decrypted), "100 - (-200) should equal 300")
}

func TestCiphertext_HomSub_Self(t *testing.T) {
	t.Parallel()
	tc := newCiphertextTestContext(t)

	pt := tc.plaintextFromInt64(t, 12345)
	ct := tc.encrypt(t, pt)

	ctDiff := ct.HomSub(ct)
	decrypted := tc.decrypt(t, ctDiff)

	expected := tc.ps.Zero()
	require.True(t, expected.Equal(decrypted), "x - x should equal 0")
}

func TestCiphertext_HomSub_AddSubInverse(t *testing.T) {
	t.Parallel()
	tc := newCiphertextTestContext(t)

	pt1 := tc.plaintextFromInt64(t, 500)
	pt2 := tc.plaintextFromInt64(t, 200)

	ct1 := tc.encrypt(t, pt1)
	ct2 := tc.encrypt(t, pt2)

	// (ct1 + ct2) - ct2 should equal ct1
	result := ct1.HomAdd(ct2).HomSub(ct2)
	decrypted := tc.decrypt(t, result)

	require.True(t, pt1.Equal(decrypted), "(x + y) - y should equal x")
}

// --- Scalar Multiplication Tests ---

func TestCiphertext_ScalarMul_PositiveScalar(t *testing.T) {
	t.Parallel()
	tc := newCiphertextTestContext(t)

	pt := tc.plaintextFromInt64(t, 100)
	ct := tc.encrypt(t, pt)

	scalar := num.N().FromUint64(5)
	ctMul := ct.ScalarMul(scalar)
	decrypted := tc.decrypt(t, ctMul)

	expected := tc.plaintextFromInt64(t, 500)
	require.True(t, expected.Equal(decrypted), "100 * 5 should equal 500")
}

func TestCiphertext_ScalarMul_Zero(t *testing.T) {
	t.Parallel()
	tc := newCiphertextTestContext(t)

	pt := tc.plaintextFromInt64(t, 12345)
	ct := tc.encrypt(t, pt)

	scalar := num.N().FromUint64(0)
	ctMul := ct.ScalarMul(scalar)
	decrypted := tc.decrypt(t, ctMul)

	expected := tc.ps.Zero()
	require.True(t, expected.Equal(decrypted), "x * 0 should equal 0")
}

func TestCiphertext_ScalarMul_One(t *testing.T) {
	t.Parallel()
	tc := newCiphertextTestContext(t)

	pt := tc.plaintextFromInt64(t, 12345)
	ct := tc.encrypt(t, pt)

	scalar := num.N().FromUint64(1)
	ctMul := ct.ScalarMul(scalar)
	decrypted := tc.decrypt(t, ctMul)

	require.True(t, pt.Equal(decrypted), "x * 1 should equal x")
}

func TestCiphertext_ScalarMul_NegativePlaintext(t *testing.T) {
	t.Parallel()
	tc := newCiphertextTestContext(t)

	pt := tc.plaintextFromInt64(t, -100)
	ct := tc.encrypt(t, pt)

	scalar := num.N().FromUint64(3)
	ctMul := ct.ScalarMul(scalar)
	decrypted := tc.decrypt(t, ctMul)

	expected := tc.plaintextFromInt64(t, -300)
	require.True(t, expected.Equal(decrypted), "-100 * 3 should equal -300")
}

func TestCiphertext_ScalarMul_LargeScalar(t *testing.T) {
	t.Parallel()
	tc := newCiphertextTestContext(t)

	pt := tc.plaintextFromInt64(t, 7)
	ct := tc.encrypt(t, pt)

	scalar := num.N().FromUint64(1000000)
	ctMul := ct.ScalarMul(scalar)
	decrypted := tc.decrypt(t, ctMul)

	expected := tc.plaintextFromInt64(t, 7000000)
	require.True(t, expected.Equal(decrypted), "7 * 1000000 should equal 7000000")
}

func TestCiphertext_ScalarMulBounded_MatchesScalarMul(t *testing.T) {
	t.Parallel()
	tc := newCiphertextTestContext(t)

	pt := tc.plaintextFromInt64(t, 123)
	ct := tc.encrypt(t, pt)

	scalar := num.N().FromUint64(255)
	ctMul1 := ct.ScalarMul(scalar)
	ctMul2 := ct.ScalarMulBounded(scalar, 8) // 255 fits in 8 bits

	dec1 := tc.decrypt(t, ctMul1)
	dec2 := tc.decrypt(t, ctMul2)

	require.True(t, dec1.Equal(dec2), "ScalarMulBounded should produce same result as ScalarMul")
}

// --- Combined Operations Tests ---

func TestCiphertext_LinearCombination(t *testing.T) {
	t.Parallel()
	tc := newCiphertextTestContext(t)

	// Compute 3*a + 2*b where a=10, b=20
	a := tc.plaintextFromInt64(t, 10)
	b := tc.plaintextFromInt64(t, 20)

	ctA := tc.encrypt(t, a)
	ctB := tc.encrypt(t, b)

	// 3*a
	ct3A := ctA.ScalarMul(num.N().FromUint64(3))
	// 2*b
	ct2B := ctB.ScalarMul(num.N().FromUint64(2))
	// 3*a + 2*b
	result := ct3A.HomAdd(ct2B)

	decrypted := tc.decrypt(t, result)
	expected := tc.plaintextFromInt64(t, 70) // 3*10 + 2*20 = 30 + 40 = 70
	require.True(t, expected.Equal(decrypted))
}

func TestCiphertext_DotProduct(t *testing.T) {
	t.Parallel()
	tc := newCiphertextTestContext(t)

	// Compute dot product: [1,2,3] · [4,5,6] = 1*4 + 2*5 + 3*6 = 4 + 10 + 18 = 32
	a := []int64{1, 2, 3}
	b := []uint64{4, 5, 6}

	// Encrypt vector a
	encA := make([]*paillier.Ciphertext, len(a))
	for i, v := range a {
		encA[i] = tc.encrypt(t, tc.plaintextFromInt64(t, v))
	}

	// Compute encrypted dot product
	var result *paillier.Ciphertext
	for i := range a {
		term := encA[i].ScalarMul(num.N().FromUint64(b[i]))
		if result == nil {
			result = term
		} else {
			result = result.HomAdd(term)
		}
	}

	decrypted := tc.decrypt(t, result)
	expected := tc.plaintextFromInt64(t, 32)
	require.True(t, expected.Equal(decrypted))
}

// --- Re-randomization Tests ---

func TestCiphertext_ReRandomise_PreservesPlaintext(t *testing.T) {
	t.Parallel()
	tc := newCiphertextTestContext(t)

	pt := tc.plaintextFromInt64(t, 42)
	ct, _, err := tc.enc.Encrypt(pt, tc.pk, crand.Reader)
	require.NoError(t, err)

	ctRand, nonce, err := ct.ReRandomise(tc.pk, crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, nonce)

	// Ciphertexts should be different
	require.False(t, ct.Equal(ctRand), "re-randomised ciphertext should be different")

	// But decrypt to the same value
	dec1 := tc.decrypt(t, ct)
	dec2 := tc.decrypt(t, ctRand)
	require.True(t, dec1.Equal(dec2), "re-randomization should preserve plaintext")
}

func TestCiphertext_ReRandomiseWithNonce_Deterministic(t *testing.T) {
	t.Parallel()
	tc := newCiphertextTestContext(t)

	pt := tc.plaintextFromInt64(t, 42)
	ct := tc.encrypt(t, pt)

	// Sample a nonce
	nonce, err := tc.pk.NonceSpace().Sample(crand.Reader)
	require.NoError(t, err)

	// Re-randomise twice with same nonce
	ct1, err := ct.ReRandomiseWithNonce(tc.pk, nonce)
	require.NoError(t, err)
	ct2, err := ct.ReRandomiseWithNonce(tc.pk, nonce)
	require.NoError(t, err)

	require.True(t, ct1.Equal(ct2), "re-randomization with same nonce should be deterministic")
}

// --- Shift Tests ---

func TestCiphertext_Shift_AddsPlaintext(t *testing.T) {
	t.Parallel()
	tc := newCiphertextTestContext(t)

	pt1 := tc.plaintextFromInt64(t, 100)
	pt2 := tc.plaintextFromInt64(t, 50)

	ct := tc.encrypt(t, pt1)
	ctShifted, err := ct.Shift(tc.pk, pt2)
	require.NoError(t, err)

	decrypted := tc.decrypt(t, ctShifted)
	expected := tc.plaintextFromInt64(t, 150)
	require.True(t, expected.Equal(decrypted), "Shift should add plaintext")
}

func TestCiphertext_Shift_NegativeDelta(t *testing.T) {
	t.Parallel()
	tc := newCiphertextTestContext(t)

	pt1 := tc.plaintextFromInt64(t, 100)
	delta := tc.plaintextFromInt64(t, -30)

	ct := tc.encrypt(t, pt1)
	ctShifted, err := ct.Shift(tc.pk, delta)
	require.NoError(t, err)

	decrypted := tc.decrypt(t, ctShifted)
	expected := tc.plaintextFromInt64(t, 70)
	require.True(t, expected.Equal(decrypted), "Shift with negative delta should subtract")
}

// --- Equality Tests ---

func TestCiphertext_Equal(t *testing.T) {
	t.Parallel()
	tc := newCiphertextTestContext(t)

	pt := tc.plaintextFromInt64(t, 42)
	nonce, err := tc.pk.NonceSpace().Sample(crand.Reader)
	require.NoError(t, err)

	// Encrypt with same nonce twice
	ct1, err := tc.enc.EncryptWithNonce(pt, tc.pk, nonce)
	require.NoError(t, err)
	ct2, err := tc.enc.EncryptWithNonce(pt, tc.pk, nonce)
	require.NoError(t, err)

	require.True(t, ct1.Equal(ct2), "same plaintext and nonce should produce equal ciphertexts")

	// Different nonces should produce different ciphertexts
	ct3 := tc.encrypt(t, pt)
	require.False(t, ct1.Equal(ct3), "different nonces should produce different ciphertexts")
}

// --- CiphertextSpace Tests ---

func TestCiphertextSpace_Sample(t *testing.T) {
	t.Parallel()
	tc := newCiphertextTestContext(t)

	cs := tc.pk.CiphertextSpace()

	ct1, err := cs.Sample(crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, ct1)

	ct2, err := cs.Sample(crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, ct2)

	// Two random samples should (almost certainly) be different
	require.False(t, ct1.Equal(ct2), "random ciphertexts should be different")
}

func TestCiphertextSpace_Contains(t *testing.T) {
	t.Parallel()
	tc := newCiphertextTestContext(t)

	cs := tc.pk.CiphertextSpace()
	ct := tc.encrypt(t, tc.plaintextFromInt64(t, 42))

	require.True(t, cs.Contains(ct))
	require.False(t, cs.Contains(nil))
}

func TestCiphertextSpace_New(t *testing.T) {
	t.Parallel()
	tc := newCiphertextTestContext(t)

	cs := tc.pk.CiphertextSpace()

	// Create a ciphertext from a nat value
	val := numct.NewNat(12345)
	ct, err := cs.New(val)
	require.NoError(t, err)
	require.NotNil(t, ct)
	require.True(t, cs.Contains(ct))
}
