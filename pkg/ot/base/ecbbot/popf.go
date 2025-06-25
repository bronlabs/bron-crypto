package ecbbot

import (
	"bytes"
	"encoding/hex"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

const (
	h2cPrefix0 = "popf-tag0-"
	h2cPrefix1 = "popf-tag1-"
)

type Popf struct {
	tag0 string
	tag1 string
}

func NewPopf(tag0, tag1 []byte) (*Popf, error) {
	if len(tag0) == 0 || len(tag1) == 0 || bytes.Equal(tag0, tag1) {
		return nil, errs.NewValidation("invalid args")
	}

	f := &Popf{
		tag0: hex.EncodeToString(tag0),
		tag1: hex.EncodeToString(tag1),
	}
	return f, nil
}

func (f *Popf) Program(x byte, y curves.Point, prng io.Reader) (s0, s1 curves.Point, err error) {
	if x > 1 || y == nil || prng == nil {
		return nil, nil, errs.NewValidation("invalid arguments")
	}

	if x == 0 {
		s1, err = y.Curve().Random(prng)
		if err != nil {
			return nil, nil, errs.WrapRandomSample(err, "cannot sample point")
		}
		h0, err := f.h0(s1)
		if err != nil {
			return nil, nil, errs.WrapHashing(err, "s1")
		}
		s0 = y.Add(h0.Neg())
	} else {
		s0, err = y.Curve().Random(prng)
		if err != nil {
			return nil, nil, errs.WrapRandomSample(err, "cannot sample point")
		}
		h1, err := f.h1(s0)
		if err != nil {
			return nil, nil, errs.WrapHashing(err, "s1")
		}
		s1 = y.Add(h1.Neg())
	}

	return s0, s1, nil
}

func (f *Popf) Eval(s0, s1 curves.Point, x byte) (y curves.Point, err error) {
	if s0 == nil || s1 == nil || x > 1 {
		return nil, errs.NewValidation("invalid arguments")
	}

	if x == 0 {
		h0, err := f.h0(s1)
		if err != nil {
			return nil, errs.WrapHashing(err, "s1")
		}
		y = s0.Add(h0)
	} else {
		h1, err := f.h1(s0)
		if err != nil {
			return nil, errs.WrapHashing(err, "s1")
		}
		y = s1.Add(h1)
	}

	return y, nil
}

func (f *Popf) h0(p curves.Point) (curves.Point, error) {
	if p == nil {
		return nil, errs.NewIsNil("p")
	}

	p0, err := p.Curve().HashWithDst(base.Hash2CurveAppTag+h2cPrefix0+f.tag0, p.ToAffineCompressed())
	if err != nil {
		return nil, errs.WrapFailed(err, "hash to curve failed")
	}
	return p0, nil
}

func (f *Popf) h1(p curves.Point) (curves.Point, error) {
	if p == nil {
		return nil, errs.NewIsNil("p")
	}

	p1, err := p.Curve().HashWithDst(base.Hash2CurveAppTag+h2cPrefix1+f.tag1, p.ToAffineCompressed())
	if err != nil {
		return nil, errs.WrapFailed(err, "hash to curve failed")
	}
	return p1, nil
}
