package pedersen_test

// Prime-group flavour: commit in a prime-order elliptic-curve group
// with scalars drawn from the curve's prime field. Binding reduces to
// the discrete log; hiding to the indistinguishability of a uniform
// scalar. Because the scalar type is Z/qZ by construction, the
// constraints that the ring-Pedersen flavour enforces with explicit
// message/witness range checks are here enforced by the type system —
// the analogues at the bottom of this file pin that asymmetry.

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
	"github.com/bronlabs/bron-crypto/pkg/commitments/pedersen"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
)

// ─── Fixtures ─────────────────────────────────────────────────────────

func newPrimeGroupScheme(t *testing.T) (
	*pedersen.Scheme[*k256.Point, *k256.Scalar],
	*pedersen.Committer[*k256.Point, *k256.Scalar],
	*pedersen.Verifier[*k256.Point, *k256.Scalar],
) {
	t.Helper()
	curve := k256.NewCurve()
	transcript := hagrid.NewTranscript("pedersen-prime-group-test")
	key, err := pedersen.ExtractPrimeGroupCommitmentKey(transcript, "h", curve.Generator())
	require.NoError(t, err)
	scheme, err := pedersen.NewPrimeGroupScheme(key)
	require.NoError(t, err)
	committer, err := scheme.Committer()
	require.NoError(t, err)
	verifier, err := scheme.Verifier()
	require.NoError(t, err)
	return scheme, committer, verifier
}

func newPrimeGroupEquivocableScheme(t *testing.T) (
	*pedersen.EquivocableScheme[*k256.Point, *k256.Scalar],
	*pedersen.Committer[*k256.Point, *k256.Scalar],
	*pedersen.Verifier[*k256.Point, *k256.Scalar],
) {
	t.Helper()
	curve := k256.NewCurve()
	trapdoor, err := pedersen.SamplePrimeGroupTrapdoorKey(curve.Generator(), pcg.NewRandomised())
	require.NoError(t, err)
	scheme, err := pedersen.NewPrimeGroupEquivocableScheme(trapdoor)
	require.NoError(t, err)
	committer, err := scheme.Committer()
	require.NoError(t, err)
	verifier, err := scheme.Verifier()
	require.NoError(t, err)
	return scheme, committer, verifier
}

func newPrimeGroupMessage(t *testing.T, value uint64) *pedersen.Message[*k256.Scalar] {
	t.Helper()
	m, err := pedersen.NewMessage(k256.NewScalarField().FromUint64(value))
	require.NoError(t, err)
	return m
}

// ─── Round-trip / completeness ────────────────────────────────────────

func TestPrimeGroup_CommitVerifyRoundTrip(t *testing.T) {
	t.Parallel()
	_, committer, verifier := newPrimeGroupScheme(t)

	message := newPrimeGroupMessage(t, 42)
	commitment, witness, err := committer.Commit(message, pcg.NewRandomised())
	require.NoError(t, err)
	require.NotNil(t, commitment)
	require.NotNil(t, witness)

	require.NoError(t, verifier.Verify(commitment, message, witness))
}

// ─── Hiding ───────────────────────────────────────────────────────────

func TestPrimeGroup_HidingFreshRandomness(t *testing.T) {
	t.Parallel()
	_, committer, _ := newPrimeGroupScheme(t)

	message := newPrimeGroupMessage(t, 7)
	c1, w1, err := committer.Commit(message, pcg.NewRandomised())
	require.NoError(t, err)
	c2, w2, err := committer.Commit(message, pcg.NewRandomised())
	require.NoError(t, err)

	require.False(t, w1.Equal(w2),
		"two independent commits must draw different witnesses (probability of collision ≈ 2^-256)")
	require.False(t, c1.Equal(c2),
		"committing twice to the same message with fresh randomness must yield distinct commitments")
}

// ─── Binding (sanity) ─────────────────────────────────────────────────
//
// We can't test computational binding directly — that would require
// breaking dlog. But we can check the contrapositive: a commitment
// cannot be opened to a message it was not produced from.

func TestPrimeGroup_VerifyRejectsWrongMessage(t *testing.T) {
	t.Parallel()
	_, committer, verifier := newPrimeGroupScheme(t)

	message := newPrimeGroupMessage(t, 1)
	wrong := newPrimeGroupMessage(t, 2)
	commitment, witness, err := committer.Commit(message, pcg.NewRandomised())
	require.NoError(t, err)

	require.NoError(t, verifier.Verify(commitment, message, witness))
	require.Error(t, verifier.Verify(commitment, wrong, witness),
		"verify must reject when the supplied message differs from the committed one")
}

func TestPrimeGroup_VerifyRejectsWrongWitness(t *testing.T) {
	t.Parallel()
	_, committer, verifier := newPrimeGroupScheme(t)

	message := newPrimeGroupMessage(t, 1)
	commitment, witness, err := committer.Commit(message, pcg.NewRandomised())
	require.NoError(t, err)

	otherWv, err := k256.NewScalarField().Random(pcg.NewRandomised())
	require.NoError(t, err)
	otherWitness, err := pedersen.NewWitness(otherWv)
	require.NoError(t, err)

	require.NoError(t, verifier.Verify(commitment, message, witness))
	require.Error(t, verifier.Verify(commitment, message, otherWitness),
		"verify must reject when the supplied witness is not the one committed under")
}

// ─── Homomorphism ────────────────────────────────────────────────────
//
// Pedersen commitments are additively homomorphic in the scalar:
//     Commit(m1, r1) · Commit(m2, r2) = Commit(m1 + m2, r1 + r2).

func TestPrimeGroup_AdditiveHomomorphism(t *testing.T) {
	t.Parallel()
	_, committer, verifier := newPrimeGroupScheme(t)

	m1 := newPrimeGroupMessage(t, 3)
	m2 := newPrimeGroupMessage(t, 5)

	c1, w1, err := committer.Commit(m1, pcg.NewRandomised())
	require.NoError(t, err)
	c2, w2, err := committer.Commit(m2, pcg.NewRandomised())
	require.NoError(t, err)

	cSum := c1.Op(c2)
	mSum := m1.Add(m2)
	wSum, err := pedersen.NewWitness(w1.Value().Add(w2.Value()))
	require.NoError(t, err)

	require.NoError(t, verifier.Verify(cSum, mSum, wSum),
		"product of commitments must verify against the sum of (messages, witnesses)")
}

// ─── Equivocation (trapdoor) ────────────────────────────────────────

func TestPrimeGroup_TrapdoorEquivocation(t *testing.T) {
	t.Parallel()
	scheme, committer, verifier := newPrimeGroupEquivocableScheme(t)

	originalMessage := newPrimeGroupMessage(t, 100)
	commitment, originalWitness, err := committer.Commit(originalMessage, pcg.NewRandomised())
	require.NoError(t, err)
	require.NoError(t, verifier.Verify(commitment, originalMessage, originalWitness))

	// The trapdoor holder picks a different opening.
	alternateMessage := newPrimeGroupMessage(t, 200)
	alternateWitness, err := scheme.Equivocate(originalMessage, originalWitness, alternateMessage, pcg.NewRandomised())
	require.NoError(t, err)
	require.False(t, originalWitness.Equal(alternateWitness),
		"equivocation must produce a different witness")

	require.NoError(t, verifier.Verify(commitment, alternateMessage, alternateWitness),
		"equivocated witness must open the original commitment to the new message")
}

// ─── Trapdoor key invariants ─────────────────────────────────────────

func TestPrimeGroup_TrapdoorReproducesH(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	trapdoor, err := pedersen.SamplePrimeGroupTrapdoorKey(curve.Generator(), pcg.NewRandomised())
	require.NoError(t, err)

	// h must equal g^λ — anyone holding λ is the equivocator. λ now lives
	// in Z/qZ rather than the curve scalar field, so we apply it via the
	// generic algebrautils.ScalarMul helper instead of g.ScalarOp.
	g := trapdoor.G()
	h := trapdoor.H()
	require.True(t, h.Equal(algebrautils.ScalarMul(g, trapdoor.Lambda())),
		"trapdoor invariant: h == g^λ")
}

// ─── Cryptographic motivation: order-wrap analogues ──────────────────
//
// The ring flavour needs explicit range checks because *num.Int does
// not know about the hidden order ord(t). The prime flavour gets the
// equivalent constraint for free: the scalar field IS Z/qZ, so any
// integer congruent to m mod q reduces to m before it can be committed.
// The two tests below pin that contract — they are the prime-side
// analogues of TestRingPedersen_OrderWrapEnablesEquivocation and
// TestRingPedersen_WitnessOrderWrapProducesSameCommitment.

func TestPrimeGroup_MessageOrderWrapHandledByScalarField(t *testing.T) {
	t.Parallel()
	// Analogue of TestRingPedersen_OrderWrapEnablesEquivocation.
	// In the ring case, m and m + ord(t) hash to the same commitment
	// under fixed randomness — a binding break unless |m| < ord(t) is
	// enforced. Here we show that "m + q" reduces to m at the type
	// level, so Commit(m, r) and Commit(m + q reduced, r) are
	// definitionally identical: the type system is the binding range
	// check.
	_, committer, verifier := newPrimeGroupScheme(t)
	sf := k256.NewScalarField()

	const raw = uint64(7)
	m := newPrimeGroupMessage(t, raw)

	q := sf.Order().Big()
	mPlusQ := new(big.Int).Add(new(big.Int).SetUint64(raw), q)
	mPlusQScalar, err := sf.FromBytesBEReduce(mPlusQ.Bytes())
	require.NoError(t, err)
	require.True(t, m.Value().Equal(mPlusQScalar),
		"the scalar field reduces m + q to m by construction — no explicit range check needed for binding")

	mShifted, err := pedersen.NewMessage(mPlusQScalar)
	require.NoError(t, err)

	commitment, witness, err := committer.Commit(m, pcg.NewRandomised())
	require.NoError(t, err)
	require.NoError(t, verifier.Verify(commitment, mShifted, witness),
		"Commit(m, r) ≡ Commit(m + q reduced, r) — the analogue of the order-wrap collision is here a tautology")
}

func TestPrimeGroup_WitnessOrderWrapHandledByScalarField(t *testing.T) {
	t.Parallel()
	// Analogue of TestRingPedersen_WitnessOrderWrapProducesSameCommitment.
	// In the ring case, t^r = t^(r + ord(t)) — witness uniqueness mod
	// ord(t) is a Sigma-proof concern, not a binding concern. In the
	// prime case, the scalar field reduces r + q to r, so any integer
	// congruent to r mod q yields the same commitment by construction.
	_, committer, verifier := newPrimeGroupScheme(t)
	sf := k256.NewScalarField()

	message := newPrimeGroupMessage(t, 42)
	commitment, witness, err := committer.Commit(message, pcg.NewRandomised())
	require.NoError(t, err)

	q := sf.Order().Big()
	rPlusQ := new(big.Int).Add(witness.Value().Cardinal().Big(), q)
	rPlusQScalar, err := sf.FromBytesBEReduce(rPlusQ.Bytes())
	require.NoError(t, err)
	require.True(t, witness.Value().Equal(rPlusQScalar),
		"the scalar field reduces r + q to r by construction")

	shiftedWitness, err := pedersen.NewWitness(rPlusQScalar)
	require.NoError(t, err)
	require.NoError(t, verifier.Verify(commitment, message, shiftedWitness),
		"Verify(C, m, r) ≡ Verify(C, m, r + q reduced) — the witness order-wrap identity is here a type-level tautology")
}

// ─── CBOR round-trips ────────────────────────────────────────────────

func TestPrimeGroup_KeyCBORRoundTrip(t *testing.T) {
	t.Parallel()
	scheme, _, _ := newPrimeGroupScheme(t)
	original := scheme.Key()

	encoded, err := original.MarshalCBOR()
	require.NoError(t, err)

	decoded := new(pedersen.Key[*k256.Point, *k256.Scalar])
	require.NoError(t, decoded.UnmarshalCBOR(encoded))

	require.True(t, original.G().Equal(decoded.G()))
	require.True(t, original.H().Equal(decoded.H()))
}

func TestPrimeGroup_CommitmentCBORRoundTrip(t *testing.T) {
	t.Parallel()
	_, committer, verifier := newPrimeGroupScheme(t)

	message := newPrimeGroupMessage(t, 9)
	commitment, witness, err := committer.Commit(message, pcg.NewRandomised())
	require.NoError(t, err)

	encoded, err := commitment.MarshalCBOR()
	require.NoError(t, err)

	decoded := new(pedersen.Commitment[*k256.Point, *k256.Scalar])
	require.NoError(t, decoded.UnmarshalCBOR(encoded))

	require.True(t, commitment.Equal(decoded))
	require.NoError(t, verifier.Verify(decoded, message, witness),
		"a CBOR-decoded commitment must verify against the original opening")
}

func TestPrimeGroup_TrapdoorCBORRoundTrip(t *testing.T) {
	t.Parallel()
	// A trapdoor must survive serialisation with both the public CRS
	// (g, h) and the secret λ intact — anyone with λ is the equivocator,
	// so any deserialiser-side discrepancy in λ silently breaks the
	// equivocation contract. We round-trip and then exercise the full
	// equivocation flow against the decoded trapdoor.
	scheme, committer, verifier := newPrimeGroupEquivocableScheme(t)
	original := scheme.TrapdoorKey()

	encoded, err := original.MarshalCBOR()
	require.NoError(t, err)

	decoded := new(pedersen.Trapdoor[*k256.Point, *k256.Scalar])
	require.NoError(t, decoded.UnmarshalCBOR(encoded))

	require.True(t, original.G().Equal(decoded.G()))
	require.True(t, original.H().Equal(decoded.H()))
	require.True(t, original.Lambda().Equal(decoded.Lambda()),
		"λ must round-trip exactly — a corrupted λ silently breaks the equivocation contract")

	// Equivocate using the decoded trapdoor against a commitment
	// produced under the original key. Wrap the decoded trapdoor in a
	// fresh EquivocableScheme so we exercise the public Equivocate path
	// rather than the internal canonicalEquivocation step.
	decodedScheme, err := pedersen.NewPrimeGroupEquivocableScheme(decoded)
	require.NoError(t, err)
	originalMessage := newPrimeGroupMessage(t, 100)
	commitment, originalWitness, err := committer.Commit(originalMessage, pcg.NewRandomised())
	require.NoError(t, err)
	alternateMessage := newPrimeGroupMessage(t, 200)
	alternateWitness, err := decodedScheme.Equivocate(originalMessage, originalWitness, alternateMessage, pcg.NewRandomised())
	require.NoError(t, err)
	require.NoError(t, verifier.Verify(commitment, alternateMessage, alternateWitness),
		"decoded trapdoor must equivocate the original commitment to the new message")
}
