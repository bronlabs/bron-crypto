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
	scheme, err := elgamal.NewScheme(curve, field)
	require.NoError(t, err)
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

// ElGamal is multiplicatively homomorphic over the group:
// Dec(Enc(m1) ⊕ Enc(m2)) == m1 · m2
func TestHomomorphicCiphertextOp(t *testing.T) {
	t.Parallel()
	scheme, enc, kg := setup(t)
	sk, pk := keygen(t, kg)
	dec, err := scheme.Decrypter(sk)
	require.NoError(t, err)

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

func TestNewSchemeRejectsNils(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	field := k256.NewScalarField()

	_, err := elgamal.NewScheme[*k256.Point, *k256.Scalar](nil, field)
	require.Error(t, err)
	_, err = elgamal.NewScheme[*k256.Point](curve, nil)
	require.Error(t, err)
}

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
