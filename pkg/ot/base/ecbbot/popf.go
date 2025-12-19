package ecbbot

import (
	"bytes"
	"io"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/ot"
)

type Popf[GE algebra.PrimeGroupElement[GE, SE], SE algebra.PrimeFieldElement[SE]] struct {
	group algebra.PrimeGroup[GE, SE]
	tag0  []byte
	tag1  []byte
}

func NewPopf[GE algebra.PrimeGroupElement[GE, SE], SE algebra.PrimeFieldElement[SE]](group algebra.PrimeGroup[GE, SE], tag0, tag1 []byte) (*Popf[GE, SE], error) {
	if len(tag0) == 0 || len(tag1) == 0 || bytes.Equal(tag0, tag1) {
		return nil, ot.ErrInvalidArgument.WithMessage("invalid args")
	}

	f := &Popf[GE, SE]{
		group: group,
		tag0:  tag0,
		tag1:  tag1,
	}
	return f, nil
}

func (f *Popf[GE, SE]) Program(x byte, y GE, prng io.Reader) (s0, s1 GE, err error) {
	var nilGE GE
	if x > 1 || prng == nil {
		return nilGE, nilGE, ot.ErrInvalidArgument.WithMessage("invalid arguments")
	}

	if x == 0 {
		s1, err = f.group.Random(prng)
		if err != nil {
			return nilGE, nilGE, errs2.Wrap(err).WithMessage("cannot sample point")
		}
		h0, err := f.h0(s1)
		if err != nil {
			return nilGE, nilGE, errs2.Wrap(err).WithMessage("s1")
		}
		s0 = y.Op(h0.OpInv())
	} else {
		s0, err = f.group.Random(prng)
		if err != nil {
			return nilGE, nilGE, errs2.Wrap(err).WithMessage("cannot sample point")
		}
		h1, err := f.h1(s0)
		if err != nil {
			return nilGE, nilGE, errs2.Wrap(err).WithMessage("s1")
		}
		s1 = y.Op(h1.OpInv())
	}

	return s0, s1, nil
}

func (f *Popf[GE, SE]) Eval(s0, s1 GE, x byte) (y GE, err error) {
	var nilGE GE
	if x > 1 {
		return nilGE, ot.ErrInvalidArgument.WithMessage("invalid arguments")
	}

	if x == 0 {
		h0, err := f.h0(s1)
		if err != nil {
			return nilGE, errs2.Wrap(err).WithMessage("s1")
		}
		y = s0.Op(h0)
	} else {
		h1, err := f.h1(s0)
		if err != nil {
			return nilGE, errs2.Wrap(err).WithMessage("s1")
		}
		y = s1.Op(h1)
	}

	return y, nil
}

func (f *Popf[GE, SE]) h0(p GE) (GE, error) {
	var nilGE GE
	p0, err := f.group.Hash(slices.Concat(f.tag0, p.Bytes()))
	if err != nil {
		return nilGE, errs2.Wrap(err).WithMessage("hash to curve failed")
	}
	return p0, nil
}

func (f *Popf[GE, SE]) h1(p GE) (GE, error) {
	var nilGE GE

	p1, err := f.group.Hash(slices.Concat(f.tag1, p.Bytes()))
	if err != nil {
		return nilGE, errs2.Wrap(err).WithMessage("hash to curve failed")
	}
	return p1, nil
}
