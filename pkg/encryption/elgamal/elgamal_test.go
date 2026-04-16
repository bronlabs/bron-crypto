package elgamal_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/encryption/elgamal"
)

// helpers shared by every test in this file.

func setup(t *testing.T) (
	*elgamal.Scheme[*k256.Point, *k256.Scalar],
	*elgamal.Encrypter[*k256.Point, *k256.Scalar],
	*elgamal.KeyGenerator[*k256.Point, *k256.Scalar],
) {
	t.Helper()
	curve := k256.NewCurve()
	field := k256.NewScalarField()
	scheme, err := elgamal.NewScheme(curve)
	require.NoError(t, err)
	require.Equal(t, scheme.ScalarRing().Name(), field.Name(), "scheme's scalar ring must match curve's scalar field")
	kg, err := scheme.Keygen()
	require.NoError(t, err)
	enc, err := scheme.Encrypter()
	require.NoError(t, err)
	return scheme, enc, kg
}

func keygen(t *testing.T, kg *elgamal.KeyGenerator[*k256.Point, *k256.Scalar]) (
	*elgamal.PrivateKey[*k256.Point, *k256.Scalar],
	*elgamal.PublicKey[*k256.Point, *k256.Scalar],
) {
	t.Helper()
	sk, pk, err := kg.Generate(pcg.NewRandomised())
	require.NoError(t, err)
	return sk, pk
}

func encrypt(
	t *testing.T,
	enc *elgamal.Encrypter[*k256.Point, *k256.Scalar],
	pt *elgamal.Plaintext[*k256.Point, *k256.Scalar],
	pk *elgamal.PublicKey[*k256.Point, *k256.Scalar],
) (*elgamal.Ciphertext[*k256.Point, *k256.Scalar], *elgamal.Nonce[*k256.Scalar]) {
	t.Helper()
	ct, nonce, err := enc.Encrypt(pt, pk, pcg.NewRandomised())
	require.NoError(t, err)
	return ct, nonce
}

func randomPlaintext(t *testing.T) *elgamal.Plaintext[*k256.Point, *k256.Scalar] {
	t.Helper()
	curve := k256.NewCurve()
	p, err := curve.Random(pcg.NewRandomised())
	require.NoError(t, err)
	pt, err := elgamal.NewPlaintext(p)
	require.NoError(t, err)
	return pt
}

func randomNonce(t *testing.T) *elgamal.Nonce[*k256.Scalar] {
	t.Helper()
	curve := k256.NewCurve()
	field := curve.ScalarField()
	nv, err := field.Random(pcg.NewRandomised())
	require.NoError(t, err)
	nonce, err := elgamal.NewNonce(nv)
	require.NoError(t, err)
	return nonce
}

// ─── Basic correctness ───────────────────────────────────────────────

func TestEncryptDecryptRoundTrip(t *testing.T) {
	t.Parallel()
	scheme, enc, kg := setup(t)
	sk, pk := keygen(t, kg)
	dec, err := scheme.Decrypter(sk)
	require.NoError(t, err)

	pt := randomPlaintext(t)
	ct, _ := encrypt(t, enc, pt, pk)

	got, err := dec.Decrypt(ct)
	require.NoError(t, err)
	require.True(t, got.Equal(pt), "decrypt(encrypt(m)) != m")
}

func TestEncryptDecryptMultipleMessages(t *testing.T) {
	t.Parallel()
	scheme, enc, kg := setup(t)
	sk, pk := keygen(t, kg)
	dec, err := scheme.Decrypter(sk)
	require.NoError(t, err)

	for range 8 {
		pt := randomPlaintext(t)
		ct, _ := encrypt(t, enc, pt, pk)
		got, err := dec.Decrypt(ct)
		require.NoError(t, err)
		require.True(t, got.Equal(pt))
	}
}

// ─── Semantic security / IND-CPA properties ──────────────────────────

// Encrypting the same message twice must produce different ciphertexts
// (probabilistic encryption). If this fails the scheme is deterministic
// and trivially breaks IND-CPA.
func TestSameMessageDifferentCiphertexts(t *testing.T) {
	t.Parallel()
	_, enc, kg := setup(t)
	_, pk := keygen(t, kg)

	pt := randomPlaintext(t)
	ct1, _ := encrypt(t, enc, pt, pk)
	ct2, _ := encrypt(t, enc, pt, pk)

	require.False(t, ct1.Equal(ct2),
		"encrypting the same plaintext twice must produce different ciphertexts (IND-CPA)")
}

// ─── Wrong-key decryption ────────────────────────────────────────────

// Decrypting with an unrelated secret key must NOT recover the original
// plaintext (except with negligible probability).
func TestDecryptWithWrongKey(t *testing.T) {
	t.Parallel()
	scheme, enc, kg := setup(t)
	_, pk1 := keygen(t, kg)
	sk2, _ := keygen(t, kg)
	dec2, err := scheme.Decrypter(sk2)
	require.NoError(t, err)

	pt := randomPlaintext(t)
	ct, _ := encrypt(t, enc, pt, pk1)

	got, err := dec2.Decrypt(ct)
	require.NoError(t, err) // decryption still "works" algebraically
	require.False(t, got.Equal(pt),
		"decrypting with a different key must not yield the correct plaintext")
}

// ─── Homomorphic properties ──────────────────────────────────────────

// ElGamal is homomorphic over the group operation.
func TestHomomorphicCiphertextOp(t *testing.T) {
	t.Parallel()
	scheme, enc, kg := setup(t)
	sk, pk := keygen(t, kg)
	dec, err := scheme.Decrypter(sk)
	require.NoError(t, err)

	t.Run("E(m1 + m2; r1 + r2) = E(m1; r1) + E(m2, r2)", func(t *testing.T) {
		t.Parallel()

		m1 := randomPlaintext(t)
		m2 := randomPlaintext(t)
		m12 := m1.Op(m2)

		r1 := randomNonce(t)
		r2 := randomNonce(t)
		r12 := r1.Op(r2)

		ct1, err := enc.EncryptWithNonce(m1, pk, r1)
		require.NoError(t, err)
		ct2, err := enc.EncryptWithNonce(m2, pk, r2)
		require.NoError(t, err)
		ct12, err := enc.EncryptWithNonce(m12, pk, r12)
		require.NoError(t, err)

		expected := ct1.Op(ct2)
		require.True(t, ct12.Equal(expected),
			"E(m1 + m2; r1 + r2) should equal E(m1; r1) + E(m2, r2) (homomorphic property with nonces)")
	})

	t.Run("Dec(Enc(m1) ⊕ Enc(m2)) == m1 · m2", func(t *testing.T) {
		t.Parallel()

		m1 := randomPlaintext(t)
		m2 := randomPlaintext(t)

		ct1, _ := encrypt(t, enc, m1, pk)
		ct2, _ := encrypt(t, enc, m2, pk)

		ctSum := ct1.Op(ct2)

		got, err := dec.Decrypt(ctSum)
		require.NoError(t, err)

		want := m1.Op(m2)
		require.True(t, got.Equal(want),
			"Dec(Enc(m1) op Enc(m2)) should equal m1 op m2 (homomorphic property)")
	})

}

// ScalarOp on a ciphertext should act as scalar exponentiation on the plaintext:
// Dec(Enc(m)^k) == m^k
func TestHomomorphicScalarOp(t *testing.T) {
	t.Parallel()
	scheme, enc, kg := setup(t)
	sk, pk := keygen(t, kg)
	dec, err := scheme.Decrypter(sk)
	require.NoError(t, err)

	field := k256.NewScalarField()
	scalar := field.FromUint64(7)

	m := randomPlaintext(t)
	ct, _ := encrypt(t, enc, m, pk)

	ctScaled := ct.ScalarOp(scalar)
	got, err := dec.Decrypt(ctScaled)
	require.NoError(t, err)

	// m^7 = m op m op ... op m (7 times), but ScalarOp on the underlying
	// group element is the same as repeated group operation.
	want, err := elgamal.NewPlaintext(m.Value().ScalarOp(scalar))
	require.NoError(t, err)

	require.True(t, got.Equal(want),
		"Dec(Enc(m)^k) should equal m^k (scalar homomorphism)")
}

// Shift: adding a known plaintext offset to a ciphertext.
// Dec(Shift(Enc(m), m')) == m · m'
func TestShift(t *testing.T) {
	t.Parallel()
	scheme, enc, kg := setup(t)
	sk, pk := keygen(t, kg)
	dec, err := scheme.Decrypter(sk)
	require.NoError(t, err)

	m := randomPlaintext(t)
	offset := randomPlaintext(t)

	ct, _ := encrypt(t, enc, m, pk)
	shifted, err := ct.Shift(pk, offset)
	require.NoError(t, err)

	got, err := dec.Decrypt(shifted)
	require.NoError(t, err)

	want := m.Op(offset)
	require.True(t, got.Equal(want),
		"Dec(Shift(Enc(m), m')) should equal m op m'")
}

// ─── Re-randomisation ────────────────────────────────────────────────

// Re-randomised ciphertext must decrypt to the same plaintext.
func TestReRandomisePreservesPlaintext(t *testing.T) {
	t.Parallel()
	scheme, enc, kg := setup(t)
	sk, pk := keygen(t, kg)
	dec, err := scheme.Decrypter(sk)
	require.NoError(t, err)

	m := randomPlaintext(t)
	ct, _ := encrypt(t, enc, m, pk)

	ct2, _, err := ct.ReRandomise(pk, pcg.NewRandomised())
	require.NoError(t, err)

	// Must decrypt to same plaintext.
	got, err := dec.Decrypt(ct2)
	require.NoError(t, err)
	require.True(t, got.Equal(m), "re-randomised ciphertext must decrypt to original plaintext")

	// But must be a different ciphertext (with overwhelming probability).
	require.False(t, ct.Equal(ct2), "re-randomised ciphertext should differ from original")
}

func TestReRandomiseWithNoncePreservesPlaintext(t *testing.T) {
	t.Parallel()
	scheme, enc, kg := setup(t)
	sk, pk := keygen(t, kg)
	dec, err := scheme.Decrypter(sk)
	require.NoError(t, err)

	field := k256.NewScalarField()
	nonceVal := field.FromUint64(999)
	nonce, err := elgamal.NewNonce(nonceVal)
	require.NoError(t, err)

	m := randomPlaintext(t)
	ct, _ := encrypt(t, enc, m, pk)

	ct2, err := ct.ReRandomiseWithNonce(pk, nonce)
	require.NoError(t, err)

	got, err := dec.Decrypt(ct2)
	require.NoError(t, err)
	require.True(t, got.Equal(m), "re-randomised ciphertext (deterministic nonce) must decrypt to original")
}

// ─── Subgroup / validation attacks ───────────────────────────────────

// A public key equal to the identity (point at infinity) would make
// h^r = O for all r, collapsing ciphertexts to (g^r, m) and leaking
// the plaintext.  The constructor must reject it.
func TestRejectIdentityPublicKey(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	identity := curve.OpIdentity()
	_, err := elgamal.NewPublicKey(identity)
	require.Error(t, err, "identity element must be rejected as public key")
}

// A private key of zero would produce pk = g^0 = identity, which is
// the same degenerate case.
func TestRejectZeroPrivateKey(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	field := k256.NewScalarField()
	zero := field.OpIdentity()
	_, err := elgamal.NewPrivateKey(curve, zero)
	require.Error(t, err, "zero scalar must be rejected as private key")
}

// A zero nonce r=0 produces ciphertext (g^0, h^0·m) = (identity, m),
// directly leaking the plaintext.
func TestRejectZeroNonce(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	zero := field.OpIdentity()
	_, err := elgamal.NewNonce(zero)
	require.Error(t, err, "zero nonce must be rejected")
}

// Nonce reuse: if two messages are encrypted with the same nonce under
// the same key, an attacker can recover m1·m2^{-1}.
// We verify this algebraically: c2_a / c2_b = m_a / m_b.
func TestNonceReuseLeaksPlaintextRatio(t *testing.T) {
	t.Parallel()
	_, enc, kg := setup(t)
	_, pk := keygen(t, kg)

	field := k256.NewScalarField()
	nonceVal := field.FromUint64(42)
	nonce, err := elgamal.NewNonce(nonceVal)
	require.NoError(t, err)

	ma := randomPlaintext(t)
	mb := randomPlaintext(t)

	ctA, err := enc.EncryptWithNonce(ma, pk, nonce)
	require.NoError(t, err)
	ctB, err := enc.EncryptWithNonce(mb, pk, nonce)
	require.NoError(t, err)

	// Both share c1 = g^r.
	require.True(t, ctA.Value().Components()[0].Equal(ctB.Value().Components()[0]),
		"same nonce must produce same c1")

	// c2_a / c2_b = (m_a * h^r) * (m_b * h^r)^{-1} = m_a * m_b^{-1}
	c2a := ctA.Value().Components()[1]
	c2b := ctB.Value().Components()[1]
	ratio := c2a.Op(c2b.OpInv())

	expectedRatio := ma.Value().Op(mb.Value().OpInv())
	require.True(t, ratio.Equal(expectedRatio),
		"nonce reuse must leak m_a * m_b^{-1} (this test documents the attack, not a defence)")
}

// ─── Malleability attacks ────────────────────────────────────────────

// Textbook ElGamal is IND-CPA but not IND-CCA2: it has no authentication
// or non-malleability guarantees. An attacker can multiply the plaintext by
// a known factor without decrypting.
// Given Enc(m) = (g^r, m·h^r), compute (g^r, m·h^r · m') to get Enc(m·m').
// Protocols that need tamper-detection must add a layer on top (MAC,
// Cramer-Shoup, or a ZK proof of ciphertext well-formedness).
func TestCiphertextMalleabilityViaShift(t *testing.T) {
	t.Parallel()
	scheme, enc, kg := setup(t)
	sk, pk := keygen(t, kg)
	dec, err := scheme.Decrypter(sk)
	require.NoError(t, err)

	m := randomPlaintext(t)
	ct, _ := encrypt(t, enc, m, pk)

	// Attacker creates a known "tweak" and shifts the ciphertext.
	attackerTweak := randomPlaintext(t)
	mauled, err := ct.Shift(pk, attackerTweak)
	require.NoError(t, err)

	// Victim decrypts the mauled ciphertext.
	got, err := dec.Decrypt(mauled)
	require.NoError(t, err)

	// The attacker can predict the result: m · tweak.
	predicted := m.Op(attackerTweak)
	require.True(t, got.Equal(predicted),
		"attacker can predictably modify plaintext via Shift (documents malleability)")
}

// ─── Encryption of identity element ──────────────────────────────────

// Encrypting the group identity (plaintext = O) should still work and
// decrypt back to identity. This is the "zero message" edge case.
func TestEncryptIdentityPlaintext(t *testing.T) {
	t.Parallel()
	scheme, enc, kg := setup(t)
	sk, pk := keygen(t, kg)
	dec, err := scheme.Decrypter(sk)
	require.NoError(t, err)

	curve := k256.NewCurve()
	identity := curve.OpIdentity()
	pt, err := elgamal.NewPlaintext(identity)
	require.NoError(t, err)

	ct, _ := encrypt(t, enc, pt, pk)
	got, err := dec.Decrypt(ct)
	require.NoError(t, err)
	require.True(t, got.Value().IsOpIdentity(),
		"encrypting the identity element should decrypt to identity")
}

// ─── Key consistency ─────────────────────────────────────────────────

// sk.Public() must equal the pk returned by Generate.
func TestKeyConsistency(t *testing.T) {
	t.Parallel()
	_, _, kg := setup(t)
	sk, pk := keygen(t, kg)
	require.True(t, sk.Public().Equal(pk), "sk.Public() must match generated pk")
}

// The public key must be g^sk.
func TestPublicKeyIsGeneratorToThePrivateKey(t *testing.T) {
	t.Parallel()
	_, _, kg := setup(t)
	curve := k256.NewCurve()

	sk, pk := keygen(t, kg)
	expected := curve.Generator().ScalarOp(sk.Value())
	require.True(t, pk.Value().Equal(expected), "pk must equal g^sk")
}

// ─── EncryptWithNonce determinism ────────────────────────────────────

// Same (message, key, nonce) triple must produce the same ciphertext.
func TestEncryptWithNonceDeterministic(t *testing.T) {
	t.Parallel()
	_, enc, kg := setup(t)
	_, pk := keygen(t, kg)

	field := k256.NewScalarField()
	nonceVal := field.FromUint64(12345)
	nonce, err := elgamal.NewNonce(nonceVal)
	require.NoError(t, err)

	m := randomPlaintext(t)

	ct1, err := enc.EncryptWithNonce(m, pk, nonce)
	require.NoError(t, err)
	ct2, err := enc.EncryptWithNonce(m, pk, nonce)
	require.NoError(t, err)

	require.True(t, ct1.Equal(ct2), "same (m, pk, nonce) must produce identical ciphertext")
}

// Verify the ciphertext structure: c1 = g^r, c2 = m · pk^r.
func TestCiphertextStructure(t *testing.T) {
	t.Parallel()
	_, enc, kg := setup(t)
	_, pk := keygen(t, kg)

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	g := curve.Generator()

	nonceVal := field.FromUint64(77)
	nonce, err := elgamal.NewNonce(nonceVal)
	require.NoError(t, err)

	m := randomPlaintext(t)
	ct, err := enc.EncryptWithNonce(m, pk, nonce)
	require.NoError(t, err)

	c1 := ct.Value().Components()[0]
	c2 := ct.Value().Components()[1]

	expectedC1 := g.ScalarOp(nonceVal)
	expectedC2 := pk.Value().ScalarOp(nonceVal).Op(m.Value())

	require.True(t, c1.Equal(expectedC1), "c1 must equal g^r")
	require.True(t, c2.Equal(expectedC2), "c2 must equal m · pk^r")
}

// ─── CBOR round-trip tests ───────────────────────────────────────────

func TestPublicKeyCBORRoundTrip(t *testing.T) {
	t.Parallel()
	_, _, kg := setup(t)
	_, pk := keygen(t, kg)

	data, err := cbor.Marshal(pk)
	require.NoError(t, err)

	got := new(elgamal.PublicKey[*k256.Point, *k256.Scalar])
	err = cbor.Unmarshal(data, got)
	require.NoError(t, err)
	require.True(t, got.Equal(pk))
}

func TestPrivateKeyCBORRoundTrip(t *testing.T) {
	t.Parallel()
	_, _, kg := setup(t)
	sk, _ := keygen(t, kg)

	data, err := cbor.Marshal(sk)
	require.NoError(t, err)

	got := new(elgamal.PrivateKey[*k256.Point, *k256.Scalar])
	err = cbor.Unmarshal(data, got)
	require.NoError(t, err)
	require.True(t, got.Equal(sk))
}

func TestCiphertextCBORRoundTrip(t *testing.T) {
	t.Parallel()
	_, enc, kg := setup(t)
	_, pk := keygen(t, kg)

	m := randomPlaintext(t)
	ct, _ := encrypt(t, enc, m, pk)

	data, err := cbor.Marshal(ct)
	require.NoError(t, err)

	got := new(elgamal.Ciphertext[*k256.Point, *k256.Scalar])
	err = cbor.Unmarshal(data, got)
	require.NoError(t, err)
	require.True(t, got.Equal(ct))
}

func TestPlaintextCBORRoundTrip(t *testing.T) {
	t.Parallel()
	m := randomPlaintext(t)

	data, err := cbor.Marshal(m)
	require.NoError(t, err)

	got := new(elgamal.Plaintext[*k256.Point, *k256.Scalar])
	err = cbor.Unmarshal(data, got)
	require.NoError(t, err)
	require.True(t, got.Equal(m))
}

func TestNonceCBORRoundTrip(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	nv := field.FromUint64(999)
	nonce, err := elgamal.NewNonce(nv)
	require.NoError(t, err)

	data, err := cbor.Marshal(nonce)
	require.NoError(t, err)

	got := new(elgamal.Nonce[*k256.Scalar])
	err = cbor.Unmarshal(data, got)
	require.NoError(t, err)
	require.True(t, got.Equal(nonce))
}

// ─── Nil / edge-case input handling ──────────────────────────────────

func TestEncryptRejectsNils(t *testing.T) {
	t.Parallel()
	_, enc, kg := setup(t)
	_, pk := keygen(t, kg)
	m := randomPlaintext(t)

	_, _, err := enc.Encrypt(nil, pk, crand.Reader)
	require.Error(t, err)
	_, _, err = enc.Encrypt(m, nil, crand.Reader)
	require.Error(t, err)
	_, _, err = enc.Encrypt(m, pk, nil)
	require.Error(t, err)
}

func TestDecryptRejectsNils(t *testing.T) {
	t.Parallel()
	scheme, _, kg := setup(t)
	sk, _ := keygen(t, kg)
	dec, err := scheme.Decrypter(sk)
	require.NoError(t, err)

	_, err = dec.Decrypt(nil)
	require.Error(t, err)
}

// ─── Clone / equality ────────────────────────────────────────────────

func TestPrivateKeyClone(t *testing.T) {
	t.Parallel()
	_, _, kg := setup(t)
	sk, _ := keygen(t, kg)
	clone := sk.Clone()
	require.True(t, clone.Equal(sk))
}

func TestPublicKeyClone(t *testing.T) {
	t.Parallel()
	_, _, kg := setup(t)
	_, pk := keygen(t, kg)
	clone := pk.Clone()
	require.True(t, clone.Equal(pk))
}

// ─── Cross-key isolation ─────────────────────────────────────────────

// Two independent key pairs must not interfere. Encrypting under pk_A
// and decrypting under sk_B must fail to recover the message, while
// sk_A correctly recovers it.
func TestCrossKeyIsolation(t *testing.T) {
	t.Parallel()
	scheme, enc, kg := setup(t)
	skA, pkA := keygen(t, kg)
	skB, _ := keygen(t, kg)
	decA, err := scheme.Decrypter(skA)
	require.NoError(t, err)
	decB, err := scheme.Decrypter(skB)
	require.NoError(t, err)

	m := randomPlaintext(t)
	ct, _ := encrypt(t, enc, m, pkA)

	gotA, err := decA.Decrypt(ct)
	require.NoError(t, err)
	require.True(t, gotA.Equal(m))

	gotB, err := decB.Decrypt(ct)
	require.NoError(t, err)
	require.False(t, gotB.Equal(m))
}

// ─── Homomorphic identity ────────────────────────────────────────────

// Enc(m) op Enc(identity) == re-encryption of m (decrypt to m).
func TestHomomorphicIdentity(t *testing.T) {
	t.Parallel()
	scheme, enc, kg := setup(t)
	sk, pk := keygen(t, kg)
	dec, err := scheme.Decrypter(sk)
	require.NoError(t, err)

	curve := k256.NewCurve()
	identity := curve.OpIdentity()
	ptId, err := elgamal.NewPlaintext(identity)
	require.NoError(t, err)

	m := randomPlaintext(t)
	ctM, _ := encrypt(t, enc, m, pk)
	ctId, _ := encrypt(t, enc, ptId, pk)

	ctCombined := ctM.Op(ctId)
	got, err := dec.Decrypt(ctCombined)
	require.NoError(t, err)
	require.True(t, got.Equal(m),
		"Enc(m) op Enc(identity) must decrypt to m")
}

// ─── Scalar op edge cases ────────────────────────────────────────────

// ScalarOp with scalar=1 should leave plaintext unchanged.
func TestScalarOpByOne(t *testing.T) {
	t.Parallel()
	scheme, enc, kg := setup(t)
	sk, pk := keygen(t, kg)
	dec, err := scheme.Decrypter(sk)
	require.NoError(t, err)

	field := k256.NewScalarField()
	one := field.FromUint64(1)

	m := randomPlaintext(t)
	ct, _ := encrypt(t, enc, m, pk)

	scaled := ct.ScalarOp(one)
	got, err := dec.Decrypt(scaled)
	require.NoError(t, err)
	require.True(t, got.Equal(m), "ScalarOp(1) must not change the plaintext")
}

// ScalarOp with scalar=2 is equivalent to ct.Op(ct).
func TestScalarOpByTwoEqualsDoubling(t *testing.T) {
	t.Parallel()
	scheme, enc, kg := setup(t)
	sk, pk := keygen(t, kg)
	dec, err := scheme.Decrypter(sk)
	require.NoError(t, err)

	field := k256.NewScalarField()
	two := field.FromUint64(2)

	m := randomPlaintext(t)
	ct, _ := encrypt(t, enc, m, pk)

	viaScalar := ct.ScalarOp(two)
	viaOp := ct.Op(ct)

	gotScalar, err := dec.Decrypt(viaScalar)
	require.NoError(t, err)
	gotOp, err := dec.Decrypt(viaOp)
	require.NoError(t, err)

	require.True(t, gotScalar.Equal(gotOp),
		"ScalarOp(2) must yield same plaintext as ct.Op(ct)")
}

// ScalarOp with scalar=0 collapses the ciphertext to the identity pair
// (g^0, (m·h^r)^0) = (O, O). The decrypted plaintext is also identity.
func TestScalarOpByZero(t *testing.T) {
	t.Parallel()
	scheme, enc, kg := setup(t)
	sk, pk := keygen(t, kg)
	dec, err := scheme.Decrypter(sk)
	require.NoError(t, err)

	field := k256.NewScalarField()
	zero := field.OpIdentity()

	m := randomPlaintext(t)
	ct, _ := encrypt(t, enc, m, pk)

	scaled := ct.ScalarOp(zero)

	// Both components must be the identity element.
	c1 := scaled.Value().Components()[0]
	c2 := scaled.Value().Components()[1]
	require.True(t, c1.IsOpIdentity(), "c1 must be identity after ScalarOp(0)")
	require.True(t, c2.IsOpIdentity(), "c2 must be identity after ScalarOp(0)")

	// Decryption: δ · γ^{-a} = O · O^{-a} = O · O = O.
	got, err := dec.Decrypt(scaled)
	require.NoError(t, err)
	require.True(t, got.Value().IsOpIdentity(),
		"ScalarOp(0) must decrypt to identity regardless of original plaintext")
}

// Enc(m, r)^k must equal Enc(m^k, r·k): scalar-operating a ciphertext
// is equivalent to encrypting the scalar-operated plaintext with the
// scalar-operated nonce.
func TestScalarOpEncryptEquivalence(t *testing.T) {
	t.Parallel()
	_, enc, kg := setup(t)
	_, pk := keygen(t, kg)

	field := k256.NewScalarField()
	k := field.FromUint64(5)

	nonceVal := field.FromUint64(3)
	nonce, err := elgamal.NewNonce(nonceVal)
	require.NoError(t, err)

	// r*k = 3*5 = 15
	scaledNonceVal := field.FromUint64(15)
	scaledNonce, err := elgamal.NewNonce(scaledNonceVal)
	require.NoError(t, err)

	m := randomPlaintext(t)

	// Encrypt then ScalarOp: (g^r, m·h^r)^k = (g^(rk), m^k·h^(rk))
	ct, err := enc.EncryptWithNonce(m, pk, nonce)
	require.NoError(t, err)
	ctScaled := ct.ScalarOp(k)

	// ScalarOp plaintext and nonce, then encrypt: Enc(m^k, rk)
	mk, err := elgamal.NewPlaintext(m.Value().ScalarOp(k))
	require.NoError(t, err)
	ctExpected, err := enc.EncryptWithNonce(mk, pk, scaledNonce)
	require.NoError(t, err)

	require.True(t, ctScaled.Equal(ctExpected),
		"Enc(m,r)^k must equal Enc(m^k, r*k)")
}

// ─── Nonce operations ───────────────────────────────────────────────

// Nonce.Op composes nonces additively: encrypting with r₁ then
// re-randomising with r₂ must equal encrypting with r₁ + r₂.
func TestNonceOp(t *testing.T) {
	t.Parallel()
	_, enc, kg := setup(t)
	_, pk := keygen(t, kg)

	field := k256.NewScalarField()
	r1, err := elgamal.NewNonce(field.FromUint64(7))
	require.NoError(t, err)
	r2, err := elgamal.NewNonce(field.FromUint64(11))
	require.NoError(t, err)

	m := randomPlaintext(t)

	// Encrypt with r1, then re-randomise with r2.
	ct, err := enc.EncryptWithNonce(m, pk, r1)
	require.NoError(t, err)
	ct2, err := ct.ReRandomiseWithNonce(pk, r2)
	require.NoError(t, err)

	// Encrypt directly with r1 + r2.
	combined := r1.Op(r2)
	require.NotNil(t, combined)
	ctDirect, err := enc.EncryptWithNonce(m, pk, combined)
	require.NoError(t, err)

	require.True(t, ct2.Equal(ctDirect),
		"Enc(m,r1) re-randomised by r2 must equal Enc(m, r1+r2)")
}

func TestNonceEqual(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()

	n1, err := elgamal.NewNonce(field.FromUint64(42))
	require.NoError(t, err)
	n2, err := elgamal.NewNonce(field.FromUint64(42))
	require.NoError(t, err)
	n3, err := elgamal.NewNonce(field.FromUint64(99))
	require.NoError(t, err)

	require.True(t, n1.Equal(n2), "equal nonce values")
	require.False(t, n1.Equal(n3), "different nonce values")
	require.False(t, n1.Equal(nil), "non-nil vs nil")

	var nilNonce *elgamal.Nonce[*k256.Scalar]
	require.True(t, nilNonce.Equal(nil), "nil vs nil")
}

// ─── Plaintext inverse and scalar ───────────────────────────────────

// m · m⁻¹ = identity.
func TestPlaintextOpInv(t *testing.T) {
	t.Parallel()
	scheme, enc, kg := setup(t)
	sk, pk := keygen(t, kg)
	dec, err := scheme.Decrypter(sk)
	require.NoError(t, err)

	m := randomPlaintext(t)
	mInv := m.OpInv()
	require.NotNil(t, mInv)

	product := m.Op(mInv)
	require.True(t, product.Value().IsOpIdentity(),
		"m op m^{-1} must be identity")

	// Verify through encryption: Dec(Enc(m) op Enc(m⁻¹)) == identity.
	ct1, _ := encrypt(t, enc, m, pk)
	ct2, _ := encrypt(t, enc, mInv, pk)
	got, err := dec.Decrypt(ct1.Op(ct2))
	require.NoError(t, err)
	require.True(t, got.Value().IsOpIdentity(),
		"Dec(Enc(m) op Enc(m^{-1})) must be identity")
}

func TestPlaintextOpInvNil(t *testing.T) {
	t.Parallel()
	var nilPT *elgamal.Plaintext[*k256.Point, *k256.Scalar]
	require.Nil(t, nilPT.OpInv())
}

// Plaintext.ScalarOp(k) must equal the group element m^k.
func TestPlaintextScalarOp(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()
	k := field.FromUint64(7)

	m := randomPlaintext(t)
	mk := m.ScalarOp(k)
	require.NotNil(t, mk)

	// Must match the raw group-level scalar op.
	expected, err := elgamal.NewPlaintext(m.Value().ScalarOp(k))
	require.NoError(t, err)
	require.True(t, mk.Equal(expected),
		"Plaintext.ScalarOp(k) must equal NewPlaintext(m.Value().ScalarOp(k))")
}

func TestPlaintextScalarOpNil(t *testing.T) {
	t.Parallel()
	m := randomPlaintext(t)
	require.Nil(t, m.ScalarOp(nil), "ScalarOp(nil) must return nil")

	var nilPT *elgamal.Plaintext[*k256.Point, *k256.Scalar]
	field := k256.NewScalarField()
	require.Nil(t, nilPT.ScalarOp(field.FromUint64(3)), "nil.ScalarOp(k) must return nil")
}

// ─── Ciphertext inverse ─────────────────────────────────────────────

// Dec(ct op ct⁻¹) == identity: the ciphertext inverse cancels the plaintext.
func TestCiphertextOpInv(t *testing.T) {
	t.Parallel()
	scheme, enc, kg := setup(t)
	sk, pk := keygen(t, kg)
	dec, err := scheme.Decrypter(sk)
	require.NoError(t, err)

	m := randomPlaintext(t)
	ct, _ := encrypt(t, enc, m, pk)

	ctInv := ct.OpInv()
	require.NotNil(t, ctInv)

	combined := ct.Op(ctInv)
	got, err := dec.Decrypt(combined)
	require.NoError(t, err)
	require.True(t, got.Value().IsOpIdentity(),
		"Dec(ct op ct^{-1}) must be identity")
}

// Dec(ct⁻¹) == m⁻¹: inverting a ciphertext inverts the plaintext.
func TestCiphertextOpInvDecryptsToPlaintextInverse(t *testing.T) {
	t.Parallel()
	scheme, enc, kg := setup(t)
	sk, pk := keygen(t, kg)
	dec, err := scheme.Decrypter(sk)
	require.NoError(t, err)

	m := randomPlaintext(t)
	ct, _ := encrypt(t, enc, m, pk)

	got, err := dec.Decrypt(ct.OpInv())
	require.NoError(t, err)

	require.True(t, got.Equal(m.OpInv()),
		"Dec(ct^{-1}) must equal m^{-1}")
}

func TestCiphertextOpInvNil(t *testing.T) {
	t.Parallel()
	var nilCT *elgamal.Ciphertext[*k256.Point, *k256.Scalar]
	require.Nil(t, nilCT.OpInv())
}

// ─── Nonce inverse and scalar ───────────────────────────────────────

// r + (-r) = 0 in Z/nZ.
func TestNonceOpInv(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	r, err := elgamal.NewNonce(field.FromUint64(42))
	require.NoError(t, err)

	rInv := r.OpInv()
	require.NotNil(t, rInv)

	// The sum of the underlying scalars must be the additive identity (zero).
	sum := r.Value().Op(rInv.Value())
	require.True(t, sum.IsOpIdentity(),
		"r + (-r) must be zero in Z/nZ")
}

func TestNonceOpInvNil(t *testing.T) {
	t.Parallel()
	var nilN *elgamal.Nonce[*k256.Scalar]
	require.Nil(t, nilN.OpInv())
}

// Nonce.ScalarOp(k) gives the nonce r·k. Encrypting m with nonce r
// then ScalarOp(k) on the ciphertext must equal encrypting m^k with
// nonce r.ScalarOp(k).
func TestNonceScalarOp(t *testing.T) {
	t.Parallel()
	_, enc, kg := setup(t)
	_, pk := keygen(t, kg)

	field := k256.NewScalarField()
	k := field.FromUint64(5)

	nonceVal := field.FromUint64(3)
	nonce, err := elgamal.NewNonce(nonceVal)
	require.NoError(t, err)

	m := randomPlaintext(t)

	// Encrypt then ScalarOp on ciphertext.
	ct, err := enc.EncryptWithNonce(m, pk, nonce)
	require.NoError(t, err)
	ctScaled := ct.ScalarOp(k)

	// ScalarOp plaintext and nonce, then encrypt.
	mk := m.ScalarOp(k)
	rk := nonce.ScalarOp(k)
	require.NotNil(t, rk)
	ctExpected, err := enc.EncryptWithNonce(mk, pk, rk)
	require.NoError(t, err)

	require.True(t, ctScaled.Equal(ctExpected),
		"Enc(m,r)^k must equal Enc(m.ScalarOp(k), r.ScalarOp(k))")
}

func TestNonceScalarOpNil(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	r, err := elgamal.NewNonce(field.FromUint64(7))
	require.NoError(t, err)

	require.Nil(t, r.ScalarOp(nil), "ScalarOp(nil) must return nil")

	var nilN *elgamal.Nonce[*k256.Scalar]
	require.Nil(t, nilN.ScalarOp(field.FromUint64(3)), "nil.ScalarOp(k) must return nil")
}

// ─── Accessor coverage ──────────────────────────────────────────────

func TestSchemeAccessors(t *testing.T) {
	t.Parallel()
	scheme, _, _ := setup(t)

	require.NotNil(t, scheme.Group())
	require.NotNil(t, scheme.ScalarRing())
	require.Equal(t, elgamal.Name, scheme.Name())

	var nilScheme *elgamal.Scheme[*k256.Point, *k256.Scalar]
	require.Nil(t, nilScheme.Group())
	require.Nil(t, nilScheme.ScalarRing())
}

func TestPublicKeyGroupAndHashCode(t *testing.T) {
	t.Parallel()
	_, _, kg := setup(t)
	_, pk := keygen(t, kg)

	require.NotNil(t, pk.Group())

	clone := pk.Clone()
	require.Equal(t, pk.HashCode(), clone.HashCode(),
		"equal public keys must have equal hash codes")

	var nilPK *elgamal.PublicKey[*k256.Point, *k256.Scalar]
	require.Nil(t, nilPK.Group())
}

func TestCiphertextScalarRing(t *testing.T) {
	t.Parallel()
	_, enc, kg := setup(t)
	_, pk := keygen(t, kg)

	m := randomPlaintext(t)
	ct, _ := encrypt(t, enc, m, pk)
	require.NotNil(t, ct.ScalarRing())

	var nilCT *elgamal.Ciphertext[*k256.Point, *k256.Scalar]
	require.Nil(t, nilCT.ScalarRing())
}

func TestNewCiphertextDirect(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()

	p1, err := curve.Random(pcg.NewRandomised())
	require.NoError(t, err)
	p2, err := curve.Random(pcg.NewRandomised())
	require.NoError(t, err)

	ct, err := elgamal.NewCiphertext(p1, p2)
	require.NoError(t, err)
	require.True(t, ct.Value().Components()[0].Equal(p1))
	require.True(t, ct.Value().Components()[1].Equal(p2))
}
