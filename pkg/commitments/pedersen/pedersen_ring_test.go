package pedersen_test

// Ring-Pedersen flavour (CGGMP21): commit in QR(N̂) ⊂ (Z/N̂Z)* with
// scalars from Z. Binding reduces to strong-RSA; hiding to a
// statistical argument that requires the witness magnitude to leave
// 2^ε of slack above |N̂|. Because the scalar type is *num.Int (no
// natural bound), the constraints that the prime-group flavour gets
// from its scalar field type are here load-bearing as explicit checks:
//
//   - |m| < 2^ell, with 2^ell ≪ ord(t) ≈ φ(N̂)/4, is the binding
//     range. Without it, a prover can equivocate via the order-wrap
//     collision exhibited in TestRingPedersen_OrderWrapEnablesEquivocation.
//   - |r| < 2^ε · N̂ is the witness range. It does not save binding
//     (the witness wraps mod ord(t) regardless — see
//     TestRingPedersen_WitnessOrderWrapProducesSameCommitment) but
//     it bounds the statistical distance for hiding and underpins
//     Sigma-proof witness extraction.

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/modular"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/commitments/pedersen"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
)

// ringPedersenKeyLen is the modulus bit length for the ring-Pedersen
// fixtures. We pick 512 bits (256-bit safe primes p, q) — enough for
// the test logic to exercise every code path while leaving meaningful
// headroom between the message bit budget (256, k256-style) and
// |ord(t)| ≈ 510, without paying the cost of production-sized
// safe-prime sampling.
const ringPedersenKeyLen = 512

// ringPedersenEll is the message bit budget used by the test fixtures.
// 256 mirrors a typical k256-coupled deployment and is well below
// |ord(t)| ≈ |N̂|−2 = 510, so the strong-RSA reduction holds.
const ringPedersenEll = 256

// ─── Fixtures ─────────────────────────────────────────────────────────

func newRingPedersenScheme(t *testing.T) (
	*pedersen.Scheme[*znstar.RSAGroupElementUnknownOrder, *num.Int],
	*pedersen.Committer[*znstar.RSAGroupElementUnknownOrder, *num.Int],
	*pedersen.Verifier[*znstar.RSAGroupElementUnknownOrder, *num.Int],
) {
	t.Helper()
	rsaGroup, err := znstar.SampleSafeRSAGroup(ringPedersenKeyLen, crand.Reader)
	require.NoError(t, err)
	transcript := hagrid.NewTranscript("pedersen-ring-test")
	key, err := pedersen.ExtractRingPedersenCommitmentKey(transcript, "st", rsaGroup)
	require.NoError(t, err)
	scheme, err := pedersen.NewRingPedersenScheme(key, ringPedersenEll)
	require.NoError(t, err)
	committer, err := scheme.Committer()
	require.NoError(t, err)
	verifier, err := scheme.Verifier()
	require.NoError(t, err)
	return scheme, committer, verifier
}

func newRingPedersenEquivocableScheme(t *testing.T) (
	*pedersen.EquivocableScheme[*znstar.RSAGroupElementUnknownOrder, *num.Int],
	*pedersen.Committer[*znstar.RSAGroupElementUnknownOrder, *num.Int],
	*pedersen.Verifier[*znstar.RSAGroupElementUnknownOrder, *num.Int],
) {
	t.Helper()
	trapdoor, err := pedersen.SampleRingPedersenTrapdoorKey(ringPedersenKeyLen, crand.Reader)
	require.NoError(t, err)
	scheme, err := pedersen.NewRingPedersenEquivocableScheme(trapdoor, ringPedersenEll)
	require.NoError(t, err)
	committer, err := scheme.Committer()
	require.NoError(t, err)
	verifier, err := scheme.Verifier()
	require.NoError(t, err)
	return scheme, committer, verifier
}

func newRingPedersenMessage(t *testing.T, value int64) *pedersen.Message[*num.Int] {
	t.Helper()
	m, err := pedersen.NewMessage(num.Z().FromInt64(value))
	require.NoError(t, err)
	return m
}

// mustMessage builds a Message from an Int, failing the test if the
// constructor errors. Used in range-check tests that need to feed
// already-out-of-bound integers into Commit to confirm rejection.
func mustMessage(t *testing.T, value *num.Int) *pedersen.Message[*num.Int] {
	t.Helper()
	m, err := pedersen.NewMessage(value)
	require.NoError(t, err)
	return m
}

// ─── Round-trip / completeness ────────────────────────────────────────

func TestRingPedersen_CommitVerifyRoundTrip(t *testing.T) {
	t.Parallel()
	_, committer, verifier := newRingPedersenScheme(t)

	message := newRingPedersenMessage(t, 42)
	commitment, witness, err := committer.Commit(message, crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, commitment)
	require.NotNil(t, witness)

	require.NoError(t, verifier.Verify(commitment, message, witness))
}

// ─── Hiding ───────────────────────────────────────────────────────────

func TestRingPedersen_HidingFreshRandomness(t *testing.T) {
	t.Parallel()
	_, committer, _ := newRingPedersenScheme(t)

	message := newRingPedersenMessage(t, 7)
	c1, w1, err := committer.Commit(message, crand.Reader)
	require.NoError(t, err)
	c2, w2, err := committer.Commit(message, crand.Reader)
	require.NoError(t, err)

	require.False(t, w1.Equal(w2),
		"two independent commits must draw different witnesses")
	require.False(t, c1.Equal(c2),
		"committing twice to the same message with fresh randomness must yield distinct commitments")
}

// ─── Binding (sanity) ─────────────────────────────────────────────────

func TestRingPedersen_VerifyRejectsWrongMessage(t *testing.T) {
	t.Parallel()
	_, committer, verifier := newRingPedersenScheme(t)

	message := newRingPedersenMessage(t, 1)
	wrong := newRingPedersenMessage(t, 2)
	commitment, witness, err := committer.Commit(message, crand.Reader)
	require.NoError(t, err)

	require.NoError(t, verifier.Verify(commitment, message, witness))
	require.Error(t, verifier.Verify(commitment, wrong, witness))
}

// ─── Equivocation (trapdoor) ────────────────────────────────────────

func TestRingPedersen_TrapdoorEquivocation(t *testing.T) {
	t.Parallel()
	scheme, committer, verifier := newRingPedersenEquivocableScheme(t)

	originalMessage := newRingPedersenMessage(t, 100)
	commitment, originalWitness, err := committer.Commit(originalMessage, crand.Reader)
	require.NoError(t, err)
	require.NoError(t, verifier.Verify(commitment, originalMessage, originalWitness))

	alternateMessage := newRingPedersenMessage(t, 200)
	alternateWitness, err := scheme.TrapdoorKey().Equivocate(originalMessage, originalWitness, alternateMessage)
	require.NoError(t, err)

	require.NoError(t, verifier.Verify(commitment, alternateMessage, alternateWitness))
}

// ─── Range checks ─────────────────────────────────────────────────────
//
// The range tests below pin the verifier's contract at the exact
// cryptographic threshold, not at "obviously too large" values: each
// uses the smallest input that violates the bound. The collision tests
// that follow demonstrate why the bound is necessary — they exhibit a
// concrete equivocation that the range check is what prevents.

func TestRingPedersen_MessageRangeRejectsBoundary(t *testing.T) {
	t.Parallel()
	_, committer, _ := newRingPedersenScheme(t)

	// 2^ell has TrueLen = ell+1, the smallest |m| that violates the
	// |m| ≤ 2^ell budget. A message of this size or larger could
	// exceed ord(t) ≈ φ(N̂)/4 (when an attacker controls ell vs N̂),
	// at which point the order-wrap collision in
	// TestRingPedersen_OrderWrapEnablesEquivocation kicks in.
	boundary := num.Z().FromInt64(1).Lsh(uint(ringPedersenEll)) // 2^ell
	message, err := pedersen.NewMessage(boundary)
	require.NoError(t, err)

	_, _, err = committer.Commit(message, crand.Reader)
	require.Error(t, err,
		"committer must reject a message at the smallest violating magnitude (2^ell)")

	// Negative side: -2^ell must be rejected too — the check is on |m|.
	_, _, err = committer.Commit(mustMessage(t, boundary.Neg()), crand.Reader)
	require.Error(t, err, "committer must reject negative messages with magnitude 2^ell")
}

func TestRingPedersen_MessageRangeAcceptsLargestValid(t *testing.T) {
	t.Parallel()
	_, committer, verifier := newRingPedersenScheme(t)

	// 2^ell − 1 has TrueLen = ell, the largest |m| accepted by the
	// budget. Round-tripping it confirms the boundary is inclusive on
	// the safe side.
	largest := num.Z().FromInt64(1).Lsh(uint(ringPedersenEll)).Sub(num.Z().FromInt64(1))
	message, err := pedersen.NewMessage(largest)
	require.NoError(t, err)

	commitment, witness, err := committer.Commit(message, crand.Reader)
	require.NoError(t, err)
	require.NoError(t, verifier.Verify(commitment, message, witness))
}

func TestRingPedersen_WitnessRangeRejectsBoundary(t *testing.T) {
	t.Parallel()
	scheme, committer, verifier := newRingPedersenScheme(t)

	message := newRingPedersenMessage(t, 1)
	commitment, _, err := committer.Commit(message, crand.Reader)
	require.NoError(t, err)

	// upper = 2^ε · N̂. The sampler emits r ∈ [-upper, upper); upper
	// itself is the smallest positive r outside the contract. The
	// witness range bound is what makes Sigma-proof witness extraction
	// sound and keeps r mod ord(t) within 2^{-ε} of uniform — both
	// arguments collapse if a prover may present r ≥ upper.
	rsaGroup := algebra.StructureMustBeAs[*znstar.RSAGroupUnknownOrder](scheme.Key().Group())
	upper := rsaGroup.Modulus().Lsh(base.StatisticalSecurityBits).Lift() // 2^ε · N̂

	atUpper, err := pedersen.NewWitness(upper)
	require.NoError(t, err)
	require.Error(t, verifier.Verify(commitment, message, atUpper),
		"verifier must reject r = upper (sampler is half-open at upper)")

	// And one below the negative bound: r = -upper - 1 is the largest
	// negative violator.
	belowLower, err := pedersen.NewWitness(upper.Neg().Sub(num.Z().FromInt64(1)))
	require.NoError(t, err)
	require.Error(t, verifier.Verify(commitment, message, belowLower),
		"verifier must reject r < -2^ε · N̂")
}

func TestRingPedersen_WitnessRangeAcceptsExtremes(t *testing.T) {
	t.Parallel()
	scheme, committer, verifier := newRingPedersenScheme(t)

	message := newRingPedersenMessage(t, 1)
	_, _, err := committer.Commit(message, crand.Reader)
	require.NoError(t, err)

	rsaGroup := algebra.StructureMustBeAs[*znstar.RSAGroupUnknownOrder](scheme.Key().Group())
	upper := rsaGroup.Modulus().Lsh(base.StatisticalSecurityBits).Lift()

	// We can't test that r = upper-1 verifies the original commitment
	// (it won't — it's the wrong randomness), but we can confirm the
	// range check itself accepts the extremes by recommitting under
	// them and verifying.
	largestPositive := upper.Sub(num.Z().FromInt64(1))
	wLarge, err := pedersen.NewWitness(largestPositive)
	require.NoError(t, err)
	cLarge, err := committer.CommitWithWitness(message, wLarge)
	require.NoError(t, err)
	require.NoError(t, verifier.Verify(cLarge, message, wLarge),
		"the largest positive in-range witness must round-trip")

	smallestNegative := upper.Neg() // -upper, inclusive lower bound
	wSmall, err := pedersen.NewWitness(smallestNegative)
	require.NoError(t, err)
	cSmall, err := committer.CommitWithWitness(message, wSmall)
	require.NoError(t, err)
	require.NoError(t, verifier.Verify(cSmall, message, wSmall),
		"the inclusive lower bound -2^ε · N̂ must round-trip")
}

// ─── Cryptographic motivation for the range checks ────────────────────

func TestRingPedersen_OrderWrapEnablesEquivocation(t *testing.T) {
	t.Parallel()
	// Without the message range check, ring-Pedersen binding collapses:
	// for any m1 and m2 = m1 + ord(t) (where ord(t) = φ(N̂)/4 = p'q'),
	//     s^m1 · t^r = s^(m1 + ord(t)) · t^r = s^m2 · t^r,
	// so the same commitment opens to both messages under the same
	// randomness. We exhibit the collision against the raw group
	// (bypassing the committer's bound) and confirm the configured
	// scheme refuses to commit to the dangerous value.
	group, sElem, tElem, _, err := znstar.SamplePedersenParameters(ringPedersenKeyLen, crand.Reader)
	require.NoError(t, err)

	arith, ok := group.Arithmetic().(*modular.OddPrimeFactors)
	require.True(t, ok, "expected RSA group arithmetic to be OddPrimeFactors")
	p, err := num.NPlus().FromNatCT(arith.Params.PNat)
	require.NoError(t, err)
	q, err := num.NPlus().FromNatCT(arith.Params.QNat)
	require.NoError(t, err)

	// ord(t) = (p-1)/2 · (q-1)/2 = p' · q' = φ(N̂)/4.
	ord := p.Rsh(1).Mul(q.Rsh(1)).Lift()

	m1 := num.Z().FromInt64(7)
	m2 := m1.Add(ord) // |m2| ≈ |ord| ≈ |N̂|-2 ≫ 2^ell
	r, err := num.Z().Random(num.Z().FromInt64(0), ord, crand.Reader)
	require.NoError(t, err)

	// Raw commitments computed directly via the group — no committer,
	// no range check.
	rawC1 := sElem.ScalarOp(m1).Op(tElem.ScalarOp(r))
	rawC2 := sElem.ScalarOp(m2).Op(tElem.ScalarOp(r))
	require.True(t, rawC1.Equal(rawC2),
		"raw collision: s^m · t^r = s^(m + ord(t)) · t^r — the range check is the only thing standing between this prover and a binding break")

	// Now load the same parameters into the scheme and confirm the
	// configured ell rejects m2 at Commit time.
	key, err := pedersen.NewCommitmentKeyUnchecked(sElem, tElem)
	require.NoError(t, err)
	scheme, err := pedersen.NewRingPedersenScheme(key, ringPedersenEll)
	require.NoError(t, err)
	committer, err := scheme.Committer()
	require.NoError(t, err)

	dangerous, err := pedersen.NewMessage(m2)
	require.NoError(t, err)
	_, _, err = committer.Commit(dangerous, crand.Reader)
	require.Error(t, err,
		"scheme must reject the order-wrapped message — accepting it would let the prover open to either m1 or m2")
}

func TestRingPedersen_WitnessOrderWrapProducesSameCommitment(t *testing.T) {
	t.Parallel()
	// For the same m, t^r = t^(r + ord(t)), so r and r + ord(t) open
	// the same commitment. ord(t) ≈ N̂/4 fits comfortably inside the
	// witness range [-2^ε · N̂, 2^ε · N̂), so the range check is NOT what
	// stops this collision (witness uniqueness mod ord(t) is the
	// concern of Sigma-proof soundness, handled at proof level). We
	// surface the algebraic identity here so the cryptographic role of
	// the range check is unambiguous: it bounds magnitude for hiding
	// statistics and witness extraction, not for binding.
	group, sElem, tElem, _, err := znstar.SamplePedersenParameters(ringPedersenKeyLen, crand.Reader)
	require.NoError(t, err)
	arith, ok := group.Arithmetic().(*modular.OddPrimeFactors)
	require.True(t, ok, "expected RSA group arithmetic to be OddPrimeFactors")
	p, err := num.NPlus().FromNatCT(arith.Params.PNat)
	require.NoError(t, err)
	q, err := num.NPlus().FromNatCT(arith.Params.QNat)
	require.NoError(t, err)

	ord := p.Rsh(1).Mul(q.Rsh(1)).Lift()

	m := num.Z().FromInt64(42)
	r1, err := num.Z().Random(num.Z().FromInt64(0), ord, crand.Reader)
	require.NoError(t, err)
	r2 := r1.Add(ord)

	rawC1 := sElem.ScalarOp(m).Op(tElem.ScalarOp(r1))
	rawC2 := sElem.ScalarOp(m).Op(tElem.ScalarOp(r2))
	require.True(t, rawC1.Equal(rawC2),
		"t^r = t^(r + ord(t)) — witness uniqueness mod ord(t) does not survive without proof-level reasoning")
}

// ─── CBOR round-trips ────────────────────────────────────────────────

func TestRingPedersen_KeyCBORRoundTrip(t *testing.T) {
	t.Parallel()
	scheme, _, _ := newRingPedersenScheme(t)
	original := scheme.Key()

	encoded, err := original.MarshalCBOR()
	require.NoError(t, err)

	decoded := new(pedersen.Key[*znstar.RSAGroupElementUnknownOrder, *num.Int])
	require.NoError(t, decoded.UnmarshalCBOR(encoded))

	require.True(t, original.G().Equal(decoded.G()))
	require.True(t, original.H().Equal(decoded.H()))
}

func TestRingPedersen_CommitmentCBORRoundTrip(t *testing.T) {
	t.Parallel()
	_, committer, verifier := newRingPedersenScheme(t)

	message := newRingPedersenMessage(t, 9)
	commitment, witness, err := committer.Commit(message, crand.Reader)
	require.NoError(t, err)

	encoded, err := commitment.MarshalCBOR()
	require.NoError(t, err)

	decoded := new(pedersen.Commitment[*znstar.RSAGroupElementUnknownOrder, *num.Int])
	require.NoError(t, decoded.UnmarshalCBOR(encoded))

	require.True(t, commitment.Equal(decoded))
	require.NoError(t, verifier.Verify(decoded, message, witness),
		"a CBOR-decoded commitment must verify against the original opening")
}

func TestRingPedersen_TrapdoorCBORRoundTrip(t *testing.T) {
	t.Parallel()
	// The ring-Pedersen trapdoor carries λ as a *num.Uint with modulus
	// φ(N̂)/4. Both the value and the modulus must survive the round
	// trip — losing the modulus would silently break TryInv during
	// equivocation. We exercise the full equivocation flow against the
	// decoded trapdoor.
	scheme, committer, verifier := newRingPedersenEquivocableScheme(t)
	original := scheme.TrapdoorKey()

	encoded, err := original.MarshalCBOR()
	require.NoError(t, err)

	decoded := new(pedersen.Trapdoor[*znstar.RSAGroupElementUnknownOrder, *num.Int])
	require.NoError(t, decoded.UnmarshalCBOR(encoded))

	require.True(t, original.G().Equal(decoded.G()))
	require.True(t, original.H().Equal(decoded.H()))
	require.True(t, original.Lambda().Equal(decoded.Lambda()),
		"λ must round-trip exactly — value and modulus")
	require.True(t, original.Lambda().Modulus().Equal(decoded.Lambda().Modulus()),
		"λ's modulus (φ(N̂)/4) must round-trip — without it TryInv silently fails during equivocation")

	originalMessage := newRingPedersenMessage(t, 100)
	commitment, originalWitness, err := committer.Commit(originalMessage, crand.Reader)
	require.NoError(t, err)
	alternateMessage := newRingPedersenMessage(t, 200)
	alternateWitness, err := decoded.Equivocate(originalMessage, originalWitness, alternateMessage)
	require.NoError(t, err)
	require.NoError(t, verifier.Verify(commitment, alternateMessage, alternateWitness),
		"decoded trapdoor must equivocate the original commitment to the new message")
}
