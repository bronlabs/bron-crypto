package ecbbot

import (
	"encoding/hex"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

const (
	kaH2cPrefix = "bron_crypto_tagged_key_agreement_"
)

type TaggedKeyAgreement struct {
	curve curves.Curve
}

func NewTaggedKeyAgreement(curve curves.Curve) (*TaggedKeyAgreement, error) {
	if curve == nil {
		return nil, errs.NewValidation("arg is nil")
	}

	ka := &TaggedKeyAgreement{
		curve: curve,
	}
	return ka, nil
}

func (ka *TaggedKeyAgreement) R(prng io.Reader) (curves.Scalar, error) {
	if prng == nil {
		return nil, errs.NewValidation("prng is nil")
	}
	a, err := ka.curve.ScalarField().Random(prng)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "random scalar")
	}
	return a, nil
}

func (*TaggedKeyAgreement) Msg1(a curves.Scalar) (curves.Point, error) {
	if a == nil {
		return nil, errs.NewValidation("a is nil")
	}
	ms := a.ScalarField().Curve().ScalarBaseMult(a)
	return ms, nil
}

func (ka *TaggedKeyAgreement) Msg2(b curves.Scalar, _ curves.Point) (curves.Point, error) {
	return ka.Msg1(b)
}

func (ka *TaggedKeyAgreement) Key1(a curves.Scalar, mr curves.Point, tag []byte) (curves.Scalar, error) {
	if a == nil || mr == nil || len(tag) == 0 {
		return nil, errs.NewValidation("a is nil")
	}
	raw := mr.ScalarMul(a)
	k, err := ka.curve.HashToScalars(1, base.Hash2CurveAppTag+kaH2cPrefix+hex.EncodeToString(tag), raw.ToAffineCompressed())
	if err != nil {
		return nil, errs.WrapFailed(err, "hash to scalar")
	}
	return k[0], nil
}

func (ka *TaggedKeyAgreement) Key2(b curves.Scalar, ms curves.Point, tag []byte) (curves.Scalar, error) {
	return ka.Key1(b, ms, tag)
}
