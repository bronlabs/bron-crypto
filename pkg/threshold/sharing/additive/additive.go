package additive

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

var (
	_ sharing.LinearScheme[*Share, curves.Scalar, curves.Scalar] = (*Scheme)(nil)
)

type Scheme struct {
	Curve curves.Curve
	Total uint
}

func NewScheme(total uint, curve curves.Curve) (*Scheme, error) {
	if total < 2 {
		return nil, errs.NewArgument("threshold cannot be less than 2")
	}
	if curve == nil {
		return nil, errs.NewIsNil("invalid curve")
	}

	return &Scheme{
		Curve: curve,
		Total: total,
	}, nil
}

func (d *Scheme) Deal(secret curves.Scalar, prng io.Reader) (shares map[types.SharingID]*Share, err error) {
	shares = make(map[types.SharingID]*Share)

	partialSum := d.Curve.ScalarField().Zero()
	for i := uint(1); i < d.Total; i++ {
		sharingId := types.SharingID(i)
		share, err := d.Curve.ScalarField().Random(prng)
		if err != nil {
			return nil, errs.WrapRandomSample(err, "could not generate random scalar")
		}
		partialSum = partialSum.Add(share)
		shares[sharingId] = &Share{
			Id:    sharingId,
			Value: share,
		}
	}
	shares[types.SharingID(d.Total)] = &Share{
		Id:    types.SharingID(d.Total),
		Value: secret.Sub(partialSum),
	}

	return shares, nil
}

func (d *Scheme) Open(shares ...*Share) (secret curves.Scalar, err error) {
	if len(shares) != int(d.Total) {
		return nil, errs.NewFailed("len(shares) != N")
	}

	sharingIds := make(map[types.SharingID]bool)
	secret = d.Curve.ScalarField().Zero()
	for _, share := range shares {
		if share == nil || share.Value == nil || share.Id > types.SharingID(d.Total) || sharingIds[share.Id] {
			return nil, errs.NewIsZero("invalid shares")
		}
		secret = secret.Add(share.Value)
		sharingIds[share.Id] = true
	}

	return secret, nil
}

func (d *Scheme) OpenInExponent(shares ...*ShareInExp) (secretInExponent curves.Point, err error) {
	if len(shares) != int(d.Total) {
		return nil, errs.NewFailed("len(shares) != N")
	}

	sharingIds := make(map[types.SharingID]bool)
	secretInExponent = d.Curve.AdditiveIdentity()
	for _, share := range shares {
		if share == nil || share.Value == nil || share.Id > types.SharingID(d.Total) || sharingIds[share.Id] {
			return nil, errs.NewIsZero("invalid shares")
		}
		secretInExponent = secretInExponent.Add(share.Value)
		sharingIds[share.Id] = true
	}

	return secretInExponent, nil
}

func (*Scheme) ShareAdd(lhs, rhs *Share) *Share {
	return lhs.Add(rhs)
}

func (*Scheme) ShareAddValue(lhs *Share, rhs curves.Scalar) *Share {
	return lhs.AddValue(rhs)
}

func (*Scheme) ShareSub(lhs, rhs *Share) *Share {
	return lhs.Sub(rhs)
}

func (*Scheme) ShareSubValue(lhs *Share, rhs curves.Scalar) *Share {
	return lhs.SubValue(rhs)
}

func (*Scheme) ShareNeg(lhs *Share) *Share {
	return lhs.Neg()
}

func (*Scheme) ShareMul(lhs *Share, rhs curves.Scalar) *Share {
	return lhs.ScalarMul(rhs)
}
