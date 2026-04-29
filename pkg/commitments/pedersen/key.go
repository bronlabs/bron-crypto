package pedersen

import (
	"fmt"
	"slices"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	ts "github.com/bronlabs/bron-crypto/pkg/transcripts"
)

// Key holds the generators defining a Pedersen commitment CRS.
type Key[E FiniteAbelianGroupElement[E, S], S algebra.RingElement[S]] struct {
	g E
	h E
}

type keyDTO[E FiniteAbelianGroupElement[E, S], S algebra.RingElement[S]] struct {
	G E `cbor:"g"`
	H E `cbor:"h"`
}

// ExtractRingPedersenCommitmentKey deterministically derives a CGGMP21 ring-Pedersen
// CRS (s, t) ∈ QR(N̂)² from the supplied transcript. The two generators are
// extracted from the transcript labels and squared into the quadratic-residue
// subgroup; extraction repeats until both squares are coprime to N̂ to avoid
// the (negligibly probable) factor-leaking elements. The returned key forgets
// the order of the underlying RSA group.
func ExtractRingPedersenCommitmentKey[A znstar.ArithmeticRSA](transcript ts.Transcript, label string, group *znstar.RSAGroup[A]) (*Key[*znstar.RSAGroupElementUnknownOrder, *num.Int], error) { // The return type must be UnknownOrder for the CommitmentKey method to be secure.
	if transcript == nil {
		return nil, ErrInvalidArgument.WithMessage("transcript cannot be nil")
	}
	if label == "" {
		return nil, ErrInvalidArgument.WithMessage("label cannot be empty")
	}
	if group == nil {
		return nil, ErrInvalidArgument.WithMessage("group cannot be nil")
	}
	var s, t *znstar.RSAGroupElement[A]
	for {
		sSqrt, err := ts.Extract(transcript, fmt.Sprintf("s_%s", label), group)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to extract sSqrt for pedersen key")
		}
		tSqrt, err := ts.Extract(transcript, fmt.Sprintf("t_%s", label), group)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to extract tSqrt for pedersen key")
		}
		s = sSqrt.Mul(sSqrt)
		t = tSqrt.Mul(tSqrt)
		if s.Value().Decrement().Nat().Coprime(group.Modulus().Nat()) && t.Value().Decrement().Nat().Coprime(group.Modulus().Nat()) {
			break
		}
	}
	out, err := NewCommitmentKeyUnchecked(s.ForgetOrder(), t.ForgetOrder())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create Pedersen commitment key")
	}
	return out, nil
}

// ExtractPrimeGroupCommitmentKey deterministically derives a Pedersen CRS in a
// prime-order group: the caller-supplied basePoint is reused as g and h is
// extracted from the transcript using the given label. The discrete log of h
// to base g is hidden by the transcript extraction, so no party knows it.
func ExtractPrimeGroupCommitmentKey[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](transcript ts.Transcript, label string, basePoint E) (*Key[E, S], error) {
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

// NewCommitmentKeyUnchecked builds a Key directly from two generators without
// going through a transcript-based setup. It still rejects nil, identity, equal
// or torsion-bearing generators, but it does not enforce that the discrete log
// of h to base g is hidden from the caller — using this constructor outside of
// trusted setup or deserialisation may break binding.
func NewCommitmentKeyUnchecked[E FiniteAbelianGroupElement[E, S], S algebra.RingElement[S]](g, h E) (*Key[E, S], error) {
	if utils.IsNil(g) || utils.IsNil(h) {
		return nil, ErrInvalidArgument.WithMessage("generators cannot be nil")
	}
	if g.Structure().Name() != h.Structure().Name() {
		return nil, ErrInvalidArgument.WithMessage("g and h must belong to the same group")
	}
	if g.Equal(h) {
		return nil, ErrInvalidArgument.WithMessage("g and h cannot be equal")
	}
	if g.IsOpIdentity() || h.IsOpIdentity() {
		return nil, ErrInvalidArgument.WithMessage("g or h cannot be the identity element")
	}
	if !g.IsTorsionFree() || !h.IsTorsionFree() {
		return nil, ErrInvalidArgument.WithMessage("g and h must be torsion-free")
	}

	k := &Key[E, S]{
		g: g,
		h: h,
	}
	return k, nil
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

// Group exposes the finite abelian group structure shared by the generators.
func (k *Key[E, S]) Group() FiniteAbelianGroup[E, S] {
	return algebra.StructureMustBeAs[FiniteAbelianGroup[E, S]](k.g.Structure())
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
