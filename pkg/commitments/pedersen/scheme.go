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
type Scheme[E FiniteAbelianGroupElement[E, S], S algebra.RingElement[S]] struct {
	key                 *Key[E, S]
	witnessValueSampler func(prng io.Reader) (S, error)
	witnessRangeCheck   func(witness *Witness[S]) error
	messageRangeCheck   func(message *Message[S]) error
}

// EquivocableScheme augments a Scheme with the trapdoor λ such that h = g^λ.
// A holder of the trapdoor can open any commitment to any message by adjusting
// the witness via Trapdoor.Equivocate. The trapdoor must therefore be kept
// secret in production deployments; the type exists primarily to support
// simulation in security proofs and zero-knowledge protocols.
type EquivocableScheme[E FiniteAbelianGroupElement[E, S], S algebra.RingElement[S]] struct {
	Scheme[E, S]

	trapdoor *Trapdoor[E, S]
}

// NewRingPedersenScheme builds a CGGMP21 ring-Pedersen scheme over the
// supplied unknown-order RSA group. messageBitBound is the protocol-level
// bit budget for messages (referred to as ℓ in the literature) and must
// be chosen well below |ord(t)| ≈ |N̂|−2 — typically the bit length of
// the consuming curve's prime order. Setting it too close to |N̂| voids
// the strong-RSA reduction and lets a prover equivocate by exploiting
// the order wrap.
func NewRingPedersenScheme(key *Key[*znstar.RSAGroupElementUnknownOrder, *num.Int], messageBitBound int) (*Scheme[*znstar.RSAGroupElementUnknownOrder, *num.Int], error) {
	if key == nil {
		return nil, ErrInvalidArgument.WithMessage("key cannot be nil")
	}
	if messageBitBound <= 0 {
		return nil, ErrInvalidArgument.WithMessage("messageBitBound must be positive")
	}
	group := algebra.StructureMustBeAs[*znstar.RSAGroupUnknownOrder](key.Group())
	nBits := group.ModulusCT().BitLen()
	// Need a strict safety gap below the RSA modulus size. The literature
	// informally wants ℓ well below |ord(t)| ≈ |N|-2; since ord(t) is hidden,
	// enforce a conservative public gap against |N|.
	if messageBitBound >= nBits-2 {
		return nil, ErrInvalidArgument.WithMessage("messageBitBound must leave headroom below |ord(t)| ≈ |N̂|-2")
	}
	if minUnknownOrderBindingSlackBits >= nBits {
		return nil, ErrInvalidArgument.WithMessage("unknown-order group modulus is too small to support the required binding slack")
	}
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
		if message.Value().Abs().TrueLen() > messageBitBound {
			return ErrInvalidArgument.WithMessage("message size is too large to commit to")
		}
		return nil
	}

	s := &Scheme[*znstar.RSAGroupElementUnknownOrder, *num.Int]{
		key:                 key,
		witnessValueSampler: witnessValueSampler,
		witnessRangeCheck:   witnessRangeChecker,
		messageRangeCheck:   messageRangeChecker,
	}
	return s, nil
}

// NewRingPedersenEquivocableScheme wraps a CGGMP21 ring-Pedersen Scheme together
// with its trapdoor λ so the holder can equivocate openings. messageBitBound is
// applied to the underlying Scheme; see NewRingPedersenScheme for the constraints.
func NewRingPedersenEquivocableScheme(trapdoor *Trapdoor[*znstar.RSAGroupElementUnknownOrder, *num.Int], messageBitBound int) (*EquivocableScheme[*znstar.RSAGroupElementUnknownOrder, *num.Int], error) {
	if trapdoor == nil {
		return nil, ErrInvalidArgument.WithMessage("trapdoor cannot be nil")
	}
	s, err := NewRingPedersenScheme(&trapdoor.Key, messageBitBound)
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
	s := &Scheme[E, S]{
		key:                 key,
		witnessValueSampler: witnessValueSampler,
		witnessRangeCheck:   primeGroupRangeChecker[*Witness[S], S],
		messageRangeCheck:   primeGroupRangeChecker[*Message[S], S],
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

func primeGroupRangeChecker[T interface {
	base.Transparent[S]
	*Witness[S] | *Message[S]
}, S algebra.PrimeFieldElement[S]](t T) error {
	if t == nil {
		return ErrInvalidArgument.WithMessage("input cannot be nil")
	}
	order := algebra.StructureMustBeAs[algebra.FiniteRing[S]](t.Value().Structure()).Order()
	if !base.PartialCompare(t.Value().Cardinal(), order).IsLessThan() {
		return ErrInvalidArgument.WithMessage("value is out of valid range")
	}
	return nil
}
