package intshamir

import (
	"io"
	"math/bits"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

var (
	_ sharing.LinearScheme[*IntShare, *saferith.Int, *saferith.Int] = (*IntScheme)(nil)
)

type IntScheme struct {
	Threshold uint
	Total     uint
}

func NewIntScheme(threshold, total uint) (*IntScheme, error) {
	s := &IntScheme{
		Threshold: threshold,
		Total:     total,
	}
	return s, nil
}

func (s *IntScheme) Deal(secret *saferith.Int, prng io.Reader) (shares map[types.SharingID]*IntShare, err error) {
	deltaBits := bits.Len64(factorial(uint64(s.Total)))
	coefficientSize := secret.AnnouncedLen() + deltaBits + int(s.Threshold-1) + base.StatisticalSecurity

	poly := make([]*saferith.Int, s.Threshold)
	poly[0] = secret.Clone()
	for i := 1; i < len(poly); i++ {
		cBytes := make([]byte, (coefficientSize+7)/8+1)
		_, err := io.ReadFull(prng, cBytes)
		if err != nil {
			return nil, errs.WrapRandomSample(err, "cannot sample coefficient")
		}
		c := new(saferith.Int)
		err = c.UnmarshalBinary(cBytes)
		if err != nil {
			return nil, errs.WrapRandomSample(err, "cannot unmarshal coefficient")
		}
		poly[i] = c
	}

	shares = make(map[types.SharingID]*IntShare)
	for id := types.SharingID(1); id <= types.SharingID(s.Total); id++ {
		value := evalInt(poly, id)
		value.Resize(value.TrueLen()) // won't leak size as these are blinded with more that statistical security bits

		shares[id] = &IntShare{
			Id:    id,
			Value: value,
		}
	}

	return shares, nil
}

func (s *IntScheme) Open(shares ...*IntShare) (secret *saferith.Int, err error) {
	secret = new(saferith.Int)
	delta := factorial(uint64(s.Total))
	deltaNat := new(saferith.Nat).SetUint64(delta)
	deltaNat.Resize(deltaNat.TrueLen())
	deltaModulus := saferith.ModulusFromNat(deltaNat)

	for i, share := range shares {
		lagrangeCoefficient := int64(delta)
		for j := range shares {
			if shares[i].Id == shares[j].Id {
				continue
			}
			lagrangeCoefficient *= int64(shares[j].Id)
			lagrangeCoefficient /= int64(shares[j].Id) - int64(shares[i].Id)
		}
		absC, signC := ct.Abs(lagrangeCoefficient)
		c := new(saferith.Int).SetUint64(absC)
		c.Neg(saferith.Choice(signC))
		c.Resize(c.TrueLen())
		secret.Add(secret, new(saferith.Int).Mul(share.Value, c, -1), -1)
	}

	abs := secret.Abs()
	sign := secret.IsNegative()
	abs.Div(abs, deltaModulus, -1)
	secret.SetNat(abs)
	secret.Neg(sign)
	return secret, nil
}

func (*IntScheme) ShareAdd(lhs, rhs *IntShare) *IntShare {
	return lhs.Add(rhs)
}

func (*IntScheme) ShareAddValue(lhs *IntShare, rhs *saferith.Int) *IntShare {
	return lhs.AddValue(rhs)
}

func (*IntScheme) ShareSub(lhs, rhs *IntShare) *IntShare {
	return lhs.Sub(rhs)
}

func (*IntScheme) ShareSubValue(lhs *IntShare, rhs *saferith.Int) *IntShare {
	return lhs.SubValue(rhs)
}

func (*IntScheme) ShareNeg(lhs *IntShare) *IntShare {
	return lhs.Neg()
}

func (*IntScheme) ShareMul(lhs *IntShare, rhs *saferith.Int) *IntShare {
	return lhs.MulScalar(rhs)
}

func factorial(n uint64) uint64 {
	f := uint64(1)
	for i := uint64(2); i <= n; i++ {
		f *= i
	}
	return f
}

func evalInt(poly []*saferith.Int, at types.SharingID) *saferith.Int {
	x := new(saferith.Int).SetUint64(uint64(at))
	y := poly[len(poly)-1].Clone()
	for i := len(poly) - 2; i >= 0; i-- {
		y.Mul(y, x, -1)
		y.Add(y, poly[i], -1)
	}

	return y
}
