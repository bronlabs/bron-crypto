package pedersencom

import (
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"github.com/bronlabs/bron-crypto/pkg/commitments/internal"
	ts "github.com/bronlabs/bron-crypto/pkg/transcripts"
)

// SampleCommitmentKey builds a commitment key whose second generator h is a
// uniformly random group element drawn from prng, paired with the group's
// canonical generator g. Crucially, h is sampled directly as a random element
// (not as g^r), so the caller never learns log_g(h); this unknown discrete-log
// relation is exactly what makes the key binding. The sampling rejects the
// identity and g itself.
func SampleCommitmentKey[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](group algebra.PrimeGroup[E, S], prng io.Reader) (*CommitmentKey[E, S], error) {
	if group == nil || prng == nil {
		return nil, ErrIsNil.WithMessage("group and prng must not be nil")
	}
	h, err := algebrautils.Random(group, prng, func(e E) bool { return !e.IsOpIdentity() && !e.Equal(group.Generator()) })
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to generate random non-identity element")
	}
	return NewCommitmentKeyUnchecked(group.Generator(), h)
}

// ExtractCommitmentKey derives the second generator h by hashing transcript
// output into the group (a nothing-up-my-sleeve construction) and pairs it with
// the caller-supplied basePoint as g. Because h is a hash-to-group output, its
// discrete log relative to g is unknown, so the resulting key is binding and
// reproducible by every party that shares the transcript. The label
// domain-separates this generator from other extractions on the same transcript.
func ExtractCommitmentKey[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](transcript ts.Transcript, label string, basePoint E) (*CommitmentKey[E, S], error) {
	if utils.IsNil(basePoint) {
		return nil, ErrInvalidArgument.WithMessage("basePoint cannot be nil")
	}
	if transcript == nil {
		return nil, ErrInvalidArgument.WithMessage("transcript cannot be nil")
	}
	if label == "" {
		return nil, ErrInvalidArgument.WithMessage("label cannot be empty")
	}

	group := algebra.StructureMustBeAs[algebra.PrimeGroup[E, S]](basePoint.Structure())
	h, err := ts.Extract(transcript, label, group)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to extract second generator for pedersen key")
	}
	out, err := NewCommitmentKeyUnchecked(basePoint, h)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create Pedersen commitment key")
	}
	return out, nil
}

// NewCommitmentKeyUnchecked assembles a commitment key from explicit generators g
// and h. It rejects nil, identical, or identity generators, but — as the name
// warns — it CANNOT verify the security-critical precondition that log_g(h) is
// unknown. Use it only when that relation has been established out of band (a
// trusted setup or ceremony). A key obtained from an untrusted source, including
// one decoded from CBOR, must not be accepted as a binding common reference
// string.
func NewCommitmentKeyUnchecked[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](g, h E) (*CommitmentKey[E, S], error) {
	if utils.IsNil(g) || utils.IsNil(h) {
		return nil, ErrIsNil.WithMessage("generators must not be nil")
	}
	if g.Equal(h) {
		return nil, ErrInvalidArgument.WithMessage("generators must be distinct")
	}
	if g.IsOpIdentity() || h.IsOpIdentity() {
		return nil, ErrIsIdentity.WithMessage("generators must not be the identity element")
	}
	return &CommitmentKey[E, S]{g: g, h: h}, nil
}

// CommitmentKey is a Pedersen common reference string: two generators g and h of
// the same prime-order group whose discrete-log relation log_g(h) is unknown.
// Under that precondition the scheme is perfectly hiding and computationally
// binding (discrete-log assumption). The key holds no secret and may be
// published; the trapdoor variant is TrapdoorKey.
type CommitmentKey[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	g E
	h E
}

type commitmentKeyDTO[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	G E `cbor:"g"`
	H E `cbor:"h"`
}

// SampleWitness draws fresh, uniform randomness r from the scalar field. Hiding
// depends on r being uniform and secret, so prng must be a cryptographically
// secure source.
func (k *CommitmentKey[E, S]) SampleWitness(prng io.Reader) (*Witness[S], error) {
	if prng == nil {
		return nil, ErrIsNil.WithMessage("prng must not be nil")
	}
	r, err := k.WitnessGroup().Random(prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to generate random witness")
	}
	return &Witness[S]{r: r}, nil
}

// CommitWithWitness deterministically computes C = g^message · h^witness. With
// log_g(h) unknown this binds message; with a uniform secret witness it perfectly
// hides it.
func (k *CommitmentKey[E, S]) CommitWithWitness(message *Message[S], witness *Witness[S]) (*Commitment[E, S], error) {
	if message == nil || witness == nil {
		return nil, ErrIsNil.WithMessage("message and witness must not be nil")
	}
	out, err := NewCommitment(k.g.ScalarOp(message.Value()).Op(k.h.ScalarOp(witness.r)))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create commitment")
	}
	return out, nil
}

// Type returns the scheme identifier Name.
func (*CommitmentKey[E, S]) Type() commitments.Name {
	return Name
}

// Open verifies that (message, witness) opens commitment, i.e. that commitment
// equals g^message · h^witness, returning commitments.ErrVerificationFailed
// otherwise. Binding guarantees no second opening exists without knowledge of
// log_g(h).
func (k *CommitmentKey[E, S]) Open(commitment *Commitment[E, S], message *Message[S], witness *Witness[S]) error {
	if err := internal.GenericOpen(k, commitment, message, witness); err != nil {
		return errs.Wrap(err).WithMessage("could not open commitment")
	}
	return nil
}

// WitnessOp adds witnesses in the scalar field. Adding the randomness of two
// commitments matches combining the commitments themselves via CommitmentOp,
// which is how the additive homomorphism keeps openings consistent.
func (k *CommitmentKey[E, S]) WitnessOp(first, second *Witness[S], rest ...*Witness[S]) (*Witness[S], error) {
	out, err := algebrautils.Op(NewWitness, k.WitnessGroup(), first, second, rest...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to combine witnesses")
	}
	return out, nil
}

// WitnessOpInv negates a witness in the scalar field, yielding the randomness of
// the inverse commitment (CommitmentOpInv).
func (*CommitmentKey[E, S]) WitnessOpInv(w *Witness[S]) (*Witness[S], error) {
	if w == nil {
		return nil, ErrIsNil.WithMessage("witness must not be nil")
	}
	out, err := NewWitness(w.r.OpInv())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new witness")
	}
	return out, nil
}

// WitnessScalarOp multiplies a witness by a scalar, matching the randomness of a
// commitment raised to that scalar (CommitmentScalarOp).
func (*CommitmentKey[E, S]) WitnessScalarOp(w *Witness[S], scalar S) (*Witness[S], error) {
	if w == nil {
		return nil, ErrIsNil.WithMessage("witness must not be nil")
	}
	if utils.IsNil(scalar) {
		return nil, ErrIsNil.WithMessage("scalar must not be nil")
	}
	out, err := NewWitness(w.r.Mul(scalar))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new witness")
	}
	return out, nil
}

// MessageOp adds committed values in the scalar field; by the homomorphism a
// commitment to the sum equals the CommitmentOp of the individual commitments.
func (k *CommitmentKey[E, S]) MessageOp(first, second *Message[S], rest ...*Message[S]) (*Message[S], error) {
	out, err := algebrautils.Op(NewMessage, k.MessageGroup(), first, second, rest...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to combine messages")
	}
	return out, nil
}

// MessageOpInv negates a committed value, matching CommitmentOpInv on its
// commitment.
func (*CommitmentKey[E, S]) MessageOpInv(m *Message[S]) (*Message[S], error) {
	if m == nil {
		return nil, ErrIsNil.WithMessage("message must not be nil")
	}
	out, err := NewMessage(m.m.OpInv())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new message")
	}
	return out, nil
}

// MessageScalarOp multiplies a committed value by a scalar, matching
// CommitmentScalarOp on its commitment.
func (*CommitmentKey[E, S]) MessageScalarOp(m *Message[S], scalar S) (*Message[S], error) {
	if m == nil {
		return nil, ErrIsNil.WithMessage("message must not be nil")
	}
	if utils.IsNil(scalar) {
		return nil, ErrIsNil.WithMessage("scalar must not be nil")
	}
	out, err := NewMessage(m.m.Mul(scalar))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new message")
	}
	return out, nil
}

// CommitmentOp combines commitments with the group operation (C1 · C2). By the
// additive homomorphism the result is a commitment to the sum of the messages
// under the sum of the witnesses.
func (k *CommitmentKey[E, S]) CommitmentOp(first, second *Commitment[E, S], rest ...*Commitment[E, S]) (*Commitment[E, S], error) {
	out, err := algebrautils.Op(NewCommitment, k.CommitmentGroup(), first, second, rest...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to combine commitments")
	}
	return out, nil
}

// CommitmentOpInv returns the group inverse of a commitment, i.e. a commitment to
// the negated message under the negated witness.
func (*CommitmentKey[E, S]) CommitmentOpInv(c *Commitment[E, S]) (*Commitment[E, S], error) {
	if c == nil {
		return nil, ErrIsNil.WithMessage("commitment must not be nil")
	}
	out, err := NewCommitment(c.v.OpInv())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new commitment")
	}
	return out, nil
}

// CommitmentScalarOp raises a commitment to a scalar, scaling both the committed
// message and its witness by that scalar.
func (*CommitmentKey[E, S]) CommitmentScalarOp(c *Commitment[E, S], scalar S) (*Commitment[E, S], error) {
	if c == nil {
		return nil, ErrIsNil.WithMessage("commitment must not be nil")
	}
	if utils.IsNil(scalar) {
		return nil, ErrIsNil.WithMessage("scalar must not be nil")
	}
	out, err := NewCommitment(c.v.ScalarOp(scalar))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new commitment")
	}
	return out, nil
}

// ReRandomise blinds a commitment by adding witnessShift · h, producing a
// fresh-looking commitment to the SAME message with witness r + witnessShift.
// It is used to unlinkably refresh a commitment; the committed value is
// unchanged.
func (k *CommitmentKey[E, S]) ReRandomise(c *Commitment[E, S], witnessShift *Witness[S]) (*Commitment[E, S], error) {
	if c == nil || witnessShift == nil {
		return nil, ErrIsNil.WithMessage("commitment and witness shift must not be nil")
	}
	out, err := NewCommitment(c.v.Op(k.h.ScalarOp(witnessShift.r)))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new commitment")
	}
	return out, nil
}

// Shift adds message · g to a commitment, producing a commitment to the shifted
// value m + message under the SAME witness. The committed value changes; the
// randomness does not.
func (k *CommitmentKey[E, S]) Shift(c *Commitment[E, S], message *Message[S]) (*Commitment[E, S], error) {
	if c == nil || message == nil {
		return nil, ErrIsNil.WithMessage("commitment and message must not be nil")
	}
	out, err := NewCommitment(c.v.Op(k.g.ScalarOp(message.Value())))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new commitment")
	}
	return out, nil
}

// G returns the first generator g, conventionally the group's canonical
// generator.
func (k *CommitmentKey[E, S]) G() E {
	return k.g
}

// H returns the second generator h. Binding requires log_g(h) to be unknown.
func (k *CommitmentKey[E, S]) H() E {
	return k.h
}

// MessageGroup returns the scalar field in which committed messages live.
func (k *CommitmentKey[E, S]) MessageGroup() algebra.PrimeField[S] {
	return algebra.StructureMustBeAs[algebra.PrimeField[S]](k.CommitmentGroup().ScalarStructure())
}

// WitnessGroup returns the scalar field from which witnesses are sampled.
func (k *CommitmentKey[E, S]) WitnessGroup() algebra.PrimeField[S] {
	return algebra.StructureMustBeAs[algebra.PrimeField[S]](k.CommitmentGroup().ScalarStructure())
}

// CommitmentGroup returns the prime-order group in which commitments live.
func (k *CommitmentKey[E, S]) CommitmentGroup() algebra.PrimeGroup[E, S] {
	return algebra.StructureMustBeAs[algebra.PrimeGroup[E, S]](k.g.Structure())
}

// Equal reports whether two keys have the same generators, treating a nil key as
// equal only to another nil key. Keys are public, so the comparison need not be
// constant time.
func (k *CommitmentKey[E, S]) Equal(other *CommitmentKey[E, S]) bool {
	if k == nil || other == nil {
		return k == other
	}
	return k.g.Equal(other.g) && k.h.Equal(other.h)
}

// HashCode combines the two generators' hash codes for use as a map key.
func (k *CommitmentKey[E, S]) HashCode() base.HashCode {
	return k.g.HashCode().Combine(k.h.HashCode())
}

// Clone returns a deep copy of the key with independently cloned generators.
func (k *CommitmentKey[E, S]) Clone() *CommitmentKey[E, S] {
	return &CommitmentKey[E, S]{
		g: k.g.Clone(),
		h: k.h.Clone(),
	}
}

// MarshalCBOR encodes the two generators g and h.
func (k *CommitmentKey[E, S]) MarshalCBOR() ([]byte, error) {
	dto := &commitmentKeyDTO[E, S]{
		G: k.g,
		H: k.h,
	}
	out, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not marshal commitment key to CBOR")
	}
	return out, nil
}

// UnmarshalCBOR decodes a commitment key and revalidates it through
// NewCommitmentKeyUnchecked. This is a deserialization trust boundary: because
// that constructor cannot establish that log_g(h) is unknown, a key decoded from
// an untrusted source MUST NOT be treated as a binding common reference string.
func (k *CommitmentKey[E, S]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[commitmentKeyDTO[E, S]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not unmarshal commitment key from CBOR")
	}
	kk, err := NewCommitmentKeyUnchecked(dto.G, dto.H)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid commitment key")
	}
	*k = *kk
	return nil
}
