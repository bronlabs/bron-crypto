package pedersen

import (
	"slices"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	ts "github.com/bronlabs/bron-crypto/pkg/transcripts"
)

// Key holds the generators defining a Pedersen commitment CRS.
type Key[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	g E
	h E
}

type keyDTO[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	G E
	H E
}

// NewCommitmentKeyUnchecked constructs a Pedersen key from caller-supplied
// generators after basic validation. The caller must ensure that the discrete
// logarithm relation between g and h is unknown.
func NewCommitmentKeyUnchecked[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](g, h E) (*Key[E, S], error) {
	if g.IsOpIdentity() || h.IsOpIdentity() {
		return nil, ErrInvalidArgument.WithMessage("g or h cannot be the identity element")
	}
	if g.Equal(h) {
		return nil, ErrInvalidArgument.WithMessage("g and h cannot be equal")
	}

	k := &Key[E, S]{
		g: g,
		h: h,
	}
	return k, nil
}

// NewCommitmentKeyFromTranscript derives h from a transcript and pairs it with
// the group's canonical generator g. This is the preferred constructor when no
// external trusted setup generated the Pedersen commitment key.
func NewCommitmentKeyFromTranscript[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](tape ts.Transcript, label string, group algebra.PrimeGroup[E, S]) (*Key[E, S], error) {
	if tape == nil || label == "" || utils.IsNil(group) {
		return nil, ErrInvalidArgument.WithMessage("invalid arguments")
	}

	g := group.Generator()
	h, err := ts.Extract(tape, label, group)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot extract h")
	}

	key, err := NewCommitmentKeyUnchecked(g, h)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create commitment key")
	}
	return key, nil
}

// G returns the first generator.
func (k *Key[E, S]) G() E {
	return k.g
}

// H returns the second generator used for hiding randomness.
func (k *Key[E, S]) H() E {
	return k.h
}

// Bytes concatenates the encoded generators.
func (k *Key[E, S]) Bytes() []byte {
	return slices.Concat(k.g.Bytes(), k.h.Bytes())
}

// Group exposes the prime group structure shared by the generators.
func (k *Key[E, S]) Group() algebra.PrimeGroup[E, S] {
	return algebra.StructureMustBeAs[algebra.PrimeGroup[E, S]](k.g.Structure())
}

// MarshalCBOR encodes the key into CBOR format.
func (k *Key[E, S]) MarshalCBOR() ([]byte, error) {
	dto := &keyDTO[E, S]{
		G: k.g,
		H: k.h,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal Pedersen key")
	}
	return data, nil
}

// UnmarshalCBOR decodes a CBOR-encoded key into the receiver.
func (k *Key[E, S]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*keyDTO[E, S]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to unmarshal Pedersen key")
	}
	k2, err := NewCommitmentKeyUnchecked(dto.G, dto.H)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot create commitment key")
	}

	*k = *k2
	return nil
}
