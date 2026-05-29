package pedersen

import (
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
)

// SampleTrapdoorKey generates a Pedersen key together with its trapdoor: it
// samples a secret scalar lambda (with lambda ∉ {0, 1}) and sets h = g^lambda
// over the group's canonical generator g. The returned key embeds lambda =
// log_g(h), which is a secret that breaks binding (it enables Equivocate), so the
// result must be handled as secret material. Use Export to obtain the public,
// binding CommitmentKey.
func SampleTrapdoorKey[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](group algebra.PrimeGroup[E, S], prng io.Reader) (*TrapdoorKey[E, S], error) {
	if group == nil || prng == nil {
		return nil, ErrIsNil.WithMessage("group and prng must not be nil")
	}
	sf := algebra.StructureMustBeAs[algebra.PrimeField[S]](group.ScalarStructure())
	lambda, err := algebrautils.Random(
		sf, prng,
		func(l S) bool { return !l.IsZero() },
		func(l S) bool { return !l.IsOne() },
	)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to sample lambda")
	}
	out, err := NewTrapdoorKey(group.Generator(), lambda)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create Pedersen trapdoor key")
	}
	return out, nil
}

// NewTrapdoorKey builds a trapdoor key from generator g and secret scalar lambda,
// deriving h = g^lambda. It rejects a nil or identity g, and
// rejects lambda ∈ {0, 1}: lambda = 0 would make h the identity and lambda = 1
// would make h equal g, each of which collapses binding. lambda is the trapdoor
// and must be kept secret.
func NewTrapdoorKey[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](g E, lambda S) (*TrapdoorKey[E, S], error) {
	if utils.IsNil(g) || utils.IsNil(lambda) {
		return nil, ErrInvalidArgument.WithMessage("generator and trapdoor value cannot be nil")
	}
	if g.IsOpIdentity() {
		return nil, ErrInvalidArgument.WithMessage("generator cannot be the identity element")
	}
	if lambda.IsZero() {
		return nil, ErrInvalidArgument.WithMessage("trapdoor value cannot be zero")
	}
	if lambda.IsOne() {
		return nil, ErrInvalidArgument.WithMessage("trapdoor value cannot be one")
	}
	t := &TrapdoorKey[E, S]{
		CommitmentKey: CommitmentKey[E, S]{
			g: g,
			h: g.ScalarOp(lambda),
		},
		lambda: lambda,
	}
	return t, nil
}

// TrapdoorKey is a Pedersen commitment key whose discrete-log relation lambda =
// log_g(h) is KNOWN. lambda is a secret trapdoor: its holder can open any
// commitment to any message via Equivocate, so the scheme is NOT binding against
// them (it remains perfectly hiding). Share only the public CommitmentKey
// returned by Export, never the TrapdoorKey itself.
type TrapdoorKey[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	CommitmentKey[E, S]

	lambda S
}

type trapdoorKeyDTO[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	G      E `cbor:"g"`
	Lambda S `cbor:"lambda"`
}

// CommitWithWitness computes the commitment as (message + lambda · witness) · g,
// which equals g^message · h^witness because h = g^lambda. It produces the exact
// same commitment as the public key but uses the trapdoor to save a scalar
// multiplication.
func (t *TrapdoorKey[E, S]) CommitWithWitness(message *Message[S], witness *Witness[S]) (*Commitment[E, S], error) {
	if message == nil || witness == nil {
		return nil, ErrIsNil.WithMessage("message and witness must not be nil")
	}
	// c = mG + rH = mG + r(lambda*G) = (m + lambda*r)G
	out, err := NewCommitment(t.g.ScalarOp(message.m.Add(t.lambda.Mul(witness.r))))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create commitment")
	}
	return out, nil
}

// Equivocate uses the trapdoor to find a witness r' that opens the same
// commitment to newMessage: r' = witness + lambda^{-1} · (message − newMessage).
// This is precisely why knowing lambda breaks binding. The prng argument is
// unused: when the original witness is uniform, the shifted r' is uniform too, so
// no distribution correction is needed.
func (t *TrapdoorKey[E, S]) Equivocate(message *Message[S], witness *Witness[S], newMessage *Message[S], _ io.Reader) (*Witness[S], error) {
	if message == nil || witness == nil || newMessage == nil {
		return nil, ErrIsNil.WithMessage("message, witness, and new message must not be nil")
	}
	// To equivocate, we need to find r' such that:
	// mG + rH = m'G + r'H
	//  => (m - m')G = ((r' - r)*lambda)G
	//  => r' = r + lambda^-1 * (m - m')
	lambdaInv, err := t.lambda.TryInv()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("trapdoor value is not invertible")
	}
	out, err := NewWitness(witness.r.Add(lambdaInv.Mul(message.m.Sub(newMessage.m))))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new witness")
	}
	return out, nil
}

// Lambda returns the secret trapdoor scalar log_g(h). The result is secret:
// exposing it lets anyone equivocate and thereby defeats binding.
func (t *TrapdoorKey[E, S]) Lambda() S {
	return t.lambda
}

// Export returns the public CommitmentKey (generators g and h only), dropping the
// trapdoor lambda so the result can be shared as a binding common reference
// string.
func (t *TrapdoorKey[E, S]) Export() *CommitmentKey[E, S] {
	return t.Clone()
}

// Equal reports whether two trapdoor keys share the same generator and trapdoor,
// treating a nil key as equal only to another nil key. h is omitted because it is
// fully determined by (g, lambda).
func (t *TrapdoorKey[E, S]) Equal(other *TrapdoorKey[E, S]) bool {
	if t == nil || other == nil {
		return t == other
	}
	return t.g.Equal(other.g) && t.lambda.Equal(other.lambda)
}

// HashCode combines the generator and the trapdoor for use as a map key.
func (t *TrapdoorKey[E, S]) HashCode() base.HashCode {
	return t.g.HashCode().Combine(t.lambda.HashCode())
}

// MarshalCBOR encodes g and the secret lambda (h is recomputed on decode). The
// output contains the trapdoor and must be protected as secret material.
func (t *TrapdoorKey[E, S]) MarshalCBOR() ([]byte, error) {
	dto := &trapdoorKeyDTO[E, S]{
		G:      t.g,
		Lambda: t.lambda,
	}
	out, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not marshal trapdoor key to CBOR")
	}
	return out, nil
}

// UnmarshalCBOR decodes a trapdoor key (g and secret lambda) and revalidates it
// through NewTrapdoorKey, recomputing h = g^lambda. This is a deserialization
// trust boundary handling secret material.
func (t *TrapdoorKey[E, S]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[trapdoorKeyDTO[E, S]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not unmarshal trapdoor key from CBOR")
	}
	tt, err := NewTrapdoorKey(dto.G, dto.Lambda)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid trapdoor key data")
	}
	*t = *tt
	return nil
}
