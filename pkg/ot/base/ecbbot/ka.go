package ecbbot

import (
	"io"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/ot"
	"github.com/bronlabs/errs-go/pkg/errs"
)

// TaggedKeyAgreement performs simple DH-style key agreement with domain-separated hashing.
type TaggedKeyAgreement[GE algebra.PrimeGroupElement[GE, SE], SE algebra.PrimeFieldElement[SE]] struct {
	group       algebra.PrimeGroup[GE, SE]
	scalarField algebra.PrimeField[SE]
}

// NewTaggedKeyAgreement constructs a keyed agreement helper over the given group.
func NewTaggedKeyAgreement[GE algebra.PrimeGroupElement[GE, SE], SE algebra.PrimeFieldElement[SE]](group algebra.PrimeGroup[GE, SE]) (*TaggedKeyAgreement[GE, SE], error) {
	scalarField, ok := group.ScalarStructure().(algebra.PrimeField[SE])
	if !ok {
		return nil, ot.ErrFailed.WithMessage("invalid group scalar structure")
	}
	ka := &TaggedKeyAgreement[GE, SE]{
		group:       group,
		scalarField: scalarField,
	}
	return ka, nil
}

func (ka *TaggedKeyAgreement[GE, SE]) R(prng io.Reader) (SE, error) {
	var nilSE SE
	if prng == nil {
		return nilSE, ot.ErrInvalidArgument.WithMessage("prng is nil")
	}
	a, err := ka.scalarField.Random(prng)
	if err != nil {
		return nilSE, errs.Wrap(err).WithMessage("random scalar")
	}

	return a, nil
}

func (ka *TaggedKeyAgreement[GE, SE]) Msg1(a SE) (GE, error) {
	ms := ka.group.ScalarBaseOp(a)
	return ms, nil
}

func (ka *TaggedKeyAgreement[GE, SE]) Msg2(b SE, _ GE) (GE, error) {
	return ka.Msg1(b)
}

// Key1 derives the sender-side key using scalar a and peer message mr with a tag.
func (ka *TaggedKeyAgreement[GE, SE]) Key1(a SE, mr GE, tag []byte) (SE, error) {
	var nilSE SE

	if a.IsZero() || !mr.IsTorsionFree() {
		return nilSE, ot.ErrInvalidArgument.WithMessage("invalid arguments")
	}
	raw := mr.ScalarOp(a)
	k, err := ka.scalarField.Hash(slices.Concat(tag, raw.Bytes()))
	if err != nil {
		return nilSE, errs.Wrap(err).WithMessage("hash to scalar")
	}
	return k, nil
}

func (ka *TaggedKeyAgreement[GE, SE]) Key2(b SE, ms GE, tag []byte) (SE, error) {
	return ka.Key1(b, ms, tag)
}
