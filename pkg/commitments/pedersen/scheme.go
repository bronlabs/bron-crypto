package pedersen

import (
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
)

// Scheme wires together the Pedersen CRS with its committer and verifier.
// equivocationLift turns the canonical trapdoor residue r₀ ∈ [0, q) into a
// witness drawn from the same distribution Commit emits; for the ring
// flavour this includes re-randomising r₀ across the honest sampler range,
// for the prime flavour it is a direct lift into the scalar field.
type Scheme[E FiniteAbelianGroupElement[E, S], S algebra.RingElement[S]] struct {
	key                 *Key[E, S]
	witnessValueSampler func(prng io.Reader) (S, error)
	witnessRangeCheck   func(witness *Witness[S]) error
	messageRangeCheck   func(message *Message[S]) error
	equivocationLift    func(r0 *num.Uint, prng io.Reader) (S, error)
}

// EquivocableScheme augments a Scheme with the trapdoor λ such that h = g^λ.
// A holder of the trapdoor can open any commitment to any message via
// EquivocableScheme.Equivocate. The trapdoor must therefore be kept secret
// in production deployments; the type exists primarily to support simulation
// in security proofs and zero-knowledge protocols.
type EquivocableScheme[E FiniteAbelianGroupElement[E, S], S algebra.RingElement[S]] struct {
	Scheme[E, S]

	trapdoor *Trapdoor[E, S]
}

// NewRingPedersenScheme builds a CGGMP21 ring-Pedersen scheme over the
// supplied unknown-order RSA group. messageSlack is the bit gap reserved
// between the accepted message size and the public modulus size: a message
// m is accepted iff |m|.AnnouncedLen() + messageSlack < |N̂|. Equivalently,
// the effective message bit budget is ℓ = |N̂| − messageSlack − 1.
//
// How to choose messageSlack:
//   - Strong-RSA binding alone needs only ℓ < |ord(t)| ≈ |N̂|−2, i.e.
//     messageSlack ≥ 2. Since ord(t) is hidden, this is the public floor.
//   - Consuming Σ-protocols (range proofs, Πenc, Πaff-g, …) extract
//     witnesses of size ≈ ℓ + |challenge| + σ; for that extraction not to
//     wrap mod ord(t), pick messageSlack ≥ |challenge| + σ + 2. In CGGMP21
//     with a λ-bit Fiat-Shamir challenge and σ = StatisticalSecurityBits,
//     this is λ + σ + 2.
//   - For a curve-scalar-sized message (ℓ ≈ |q| ≈ 256) over |N̂| = 2048,
//     messageSlack = |N̂| − |q| (≈ 1792) is a comfortable default that
//     leaves headroom for any consuming protocol.
//
// Setting messageSlack at the floor (2) keeps binding intact but voids the
// soundness of any Σ-protocol layered on top, since extracted witnesses can
// wrap mod ord(t).
func NewRingPedersenScheme(key *Key[*znstar.RSAGroupElementUnknownOrder, *num.Int], messageSlack int) (*Scheme[*znstar.RSAGroupElementUnknownOrder, *num.Int], error) {
	if key == nil {
		return nil, ErrInvalidArgument.WithMessage("key cannot be nil")
	}
	// Slack of 2 is the public floor that keeps ℓ strictly below
	// |ord(t)| ≈ |N̂|−2. Soundness of consuming Σ-protocols requires more;
	// see the function comment for guidance on the correct value.
	if messageSlack < 2 {
		return nil, ErrInvalidArgument.WithMessage("messageSlack must be >= 2 to leave headroom below |ord(t)| ≈ |N̂|-2")
	}
	group := algebra.StructureMustBeAs[*znstar.RSAGroupUnknownOrder](key.Group())
	nBits := group.ModulusCT().BitLen()
	upper := group.Modulus().Lsh(base.StatisticalSecurityBits).Lift()
	lower := upper.Neg()
	witnessValueSampler := func(prng io.Reader) (*num.Int, error) {
		if prng == nil {
			return nil, ErrInvalidArgument.WithMessage("prng cannot be nil")
		}
		wv, err := num.Z().Random(lower, upper, prng)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot sample witness value")
		}
		return wv, nil
	}
	witnessRangeChecker := func(witness *Witness[*num.Int]) error {
		if witness == nil {
			return ErrInvalidArgument.WithMessage("witness cannot be nil")
		}
		// Sampler emits r ∈ [lower, upper); accept the same half-open range.
		if base.Compare(witness.Value(), lower).IsLessThan() || !base.Compare(witness.Value(), upper).IsLessThan() {
			return ErrInvalidArgument.WithMessage("witness value is out of valid range")
		}
		return nil
	}
	messageRangeChecker := func(message *Message[*num.Int]) error {
		if message == nil {
			return ErrInvalidArgument.WithMessage("message cannot be nil")
		}
		if message.Value().Abs().TrueLen()+messageSlack >= nBits {
			return ErrInvalidArgument.WithMessage("message size is too large to commit to")
		}
		return nil
	}
	// Lift r₀ ∈ [0, q) into the honest sampler range [lower, upper) by
	// adding a uniform multiple of q. The output distribution equals the
	// honest distribution conditioned on residue ≡ r₀ (mod q), which is
	// statistically ≤ 2^{-σ} from honest — without this re-randomisation
	// the equivocated witness would be trivially distinguishable (always
	// non-negative and ~σ+2 bits smaller than honest).
	equivocationLift := func(r0 *num.Uint, prng io.Reader) (*num.Int, error) {
		if r0 == nil {
			return nil, ErrInvalidArgument.WithMessage("r0 cannot be nil")
		}
		if prng == nil {
			return nil, ErrInvalidArgument.WithMessage("prng cannot be nil")
		}
		q := r0.Modulus().Lift()
		r0Int := r0.Lift()
		one := num.Z().FromInt64(1)
		// kMin = ceil((lower - r0) / q): EuclideanDiv gives floor for any
		// sign, so add 1 when there is a non-zero remainder.
		kMinFloor, kMinRem, err := lower.Sub(r0Int).EuclideanDivVarTime(q)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to compute lower offset bound")
		}
		kMin := kMinFloor
		if !kMinRem.IsZero() {
			kMin = kMinFloor.Add(one)
		}
		// kMax = floor((upper - 1 - r0) / q); upper is positive and r0 < q,
		// so the dividend is positive and floor is direct.
		kMax, _, err := upper.Sub(one).Sub(r0Int).EuclideanDivVarTime(q)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to compute upper offset bound")
		}
		k, err := num.Z().Random(kMin, kMax.Add(one), prng)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to sample re-randomisation offset")
		}
		return r0Int.Add(k.Mul(q)), nil
	}

	s := &Scheme[*znstar.RSAGroupElementUnknownOrder, *num.Int]{
		key:                 key,
		witnessValueSampler: witnessValueSampler,
		witnessRangeCheck:   witnessRangeChecker,
		messageRangeCheck:   messageRangeChecker,
		equivocationLift:    equivocationLift,
	}
	return s, nil
}

// NewRingPedersenEquivocableScheme wraps a CGGMP21 ring-Pedersen Scheme together
// with its trapdoor λ so the holder can equivocate openings. messageSlack is
// forwarded to the underlying Scheme; see NewRingPedersenScheme for how to
// choose it.
func NewRingPedersenEquivocableScheme(trapdoor *Trapdoor[*znstar.RSAGroupElementUnknownOrder, *num.Int], messageSlack int) (*EquivocableScheme[*znstar.RSAGroupElementUnknownOrder, *num.Int], error) {
	if trapdoor == nil {
		return nil, ErrInvalidArgument.WithMessage("trapdoor cannot be nil")
	}
	s, err := NewRingPedersenScheme(&trapdoor.Key, messageSlack)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create underlying Pedersen scheme")
	}
	return &EquivocableScheme[*znstar.RSAGroupElementUnknownOrder, *num.Int]{
		Scheme:   *s,
		trapdoor: trapdoor,
	}, nil
}

// NewPrimeGroupScheme builds a Pedersen scheme over a prime-order group. Both
// messages and witnesses live in the group's scalar field, so range checks
// reduce to verifying that a value's canonical representative is below the
// scalar field order; equivalently, every field element is a valid input.
func NewPrimeGroupScheme[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](key *Key[E, S]) (*Scheme[E, S], error) {
	if key == nil {
		return nil, ErrInvalidArgument.WithMessage("key cannot be nil")
	}
	witnessValueSampler := func(prng io.Reader) (S, error) {
		field := algebra.StructureMustBeAs[algebra.FiniteRing[S]](key.Group().ScalarStructure())
		return algebrautils.RandomNonIdentity(field, prng)
	}
	// The honest witness sampler emits uniform field elements (canonical
	// representative in [0, q)), so the trapdoor's canonical r₀ already
	// matches that distribution — lift via the field's reducer and ignore
	// prng. A nil prng is tolerated because no randomness is consumed.
	fromBytes, ok := any(key.Group().ScalarStructure()).(interface {
		FromBytesBEReduce([]byte) (S, error)
	})
	if !ok {
		return nil, ErrInvalidArgument.WithMessage("scalar structure does not support FromBytesBEReduce")
	}
	equivocationLift := func(r0 *num.Uint, _ io.Reader) (S, error) {
		var zero S
		if r0 == nil {
			return zero, ErrInvalidArgument.WithMessage("r0 cannot be nil")
		}
		out, err := fromBytes.FromBytesBEReduce(r0.BytesBE())
		if err != nil {
			return zero, errs.Wrap(err).WithMessage("failed to lift r0 into the scalar field")
		}
		return out, nil
	}
	s := &Scheme[E, S]{
		key:                 key,
		witnessValueSampler: witnessValueSampler,
		witnessRangeCheck:   func(*Witness[S]) error { return nil }, // enforced at compile time.
		messageRangeCheck:   func(*Message[S]) error { return nil }, // enforced at compile time.
		equivocationLift:    equivocationLift,
	}
	return s, nil
}

// NewPrimeGroupEquivocableScheme wraps a prime-group Pedersen Scheme together
// with its trapdoor λ so the holder can equivocate openings.
func NewPrimeGroupEquivocableScheme[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](trapdoor *Trapdoor[E, S]) (*EquivocableScheme[E, S], error) {
	if trapdoor == nil {
		return nil, ErrInvalidArgument.WithMessage("trapdoor cannot be nil")
	}
	s, err := NewPrimeGroupScheme(&trapdoor.Key)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create underlying Pedersen scheme")
	}
	return &EquivocableScheme[E, S]{
		Scheme:   *s,
		trapdoor: trapdoor,
	}, nil
}

// Name returns the identifier of the Pedersen commitment scheme.
func (*Scheme[_, _]) Name() commitments.Name {
	return Name
}

// Committer returns a committer configured with the scheme key.
func (s *Scheme[E, S]) Committer(opts ...CommitterOption[E, S]) (*Committer[E, S], error) {
	out := &Committer[E, S]{
		key:                 s.key,
		witnessValueSampler: s.witnessValueSampler,
		witnessRangeCheck:   s.witnessRangeCheck,
		messageRangeCheck:   s.messageRangeCheck,
	}
	for _, opt := range opts {
		if err := opt(out); err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot apply committer option")
		}
	}
	return out, nil
}

// Verifier returns a verifier compatible with commitments produced by this scheme.
func (s *Scheme[E, S]) Verifier(opts ...VerifierOption[E, S]) (*Verifier[E, S], error) {
	committingParty, err := s.Committer()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create internal committer for verifier")
	}
	generic := commitments.NewGenericVerifier(committingParty)
	v := &Verifier[E, S]{
		GenericVerifier:   *generic,
		witnessRangeCheck: s.witnessRangeCheck,
		messageRangeCheck: s.messageRangeCheck,
	}
	for _, opt := range opts {
		if err := opt(v); err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot apply verifier option")
		}
	}
	return v, nil
}

// Key exposes the scheme CRS.
func (s *Scheme[E, S]) Key() *Key[E, S] {
	return s.key
}

// Group returns the prime group used by the scheme.
func (s *Scheme[E, S]) Group() FiniteAbelianGroup[E, S] {
	return s.key.Group()
}

// TrapdoorKey returns the underlying trapdoor. Callers must treat the result as secret.
func (s *EquivocableScheme[E, S]) TrapdoorKey() *Trapdoor[E, S] {
	return s.trapdoor
}

// Equivocate produces a witness that opens the same commitment to newMessage,
// given (message, witness) that already opens it. The trapdoor handles the
// algebraic step (computing the canonical residue r₀ ∈ [0, q)); the scheme's
// equivocationLift handles the flavour-specific lift of r₀ back into the
// honest witness distribution. For ring-Pedersen this re-randomises r₀ across
// the σ-bit-larger honest range so the equivocated witness is statistically
// indistinguishable from a fresh honest one (mandatory for any consuming ZK
// simulator); for the prime flavour it is a direct lift into the scalar field.
func (s *EquivocableScheme[E, S]) Equivocate(message *Message[S], witness *Witness[S], newMessage *Message[S], prng io.Reader) (*Witness[S], error) {
	r0, err := s.trapdoor.canonicalEquivocation(message, witness, newMessage)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot compute canonical equivocation")
	}
	value, err := s.equivocationLift(r0, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot lift equivocated witness")
	}
	out, err := NewWitness(value)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create equivocated witness")
	}
	return out, nil
}
