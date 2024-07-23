package intshamir

import (
	crand "crypto/rand"
	"encoding/hex"
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

type Share struct {
	Id    types.SharingID
	Value *saferith.Nat
}

type Dealer struct {
	t uint
	n uint

	delta int64
	d     *saferith.Nat
	d2    *saferith.Nat
	d3    *saferith.Nat
	d10   *saferith.Nat
}

func NewDealer(t, n uint) *Dealer {
	d := &Dealer{
		t: t,
		n: n,
	}
	d.precompute()
	return d
}

func (d *Dealer) Deal(value, maxValue *saferith.Nat, prng io.Reader) ([]*Share, error) {
	maxCoefficientFactor := new(saferith.Nat).Mul(maxValue, maxValue, -1)
	maxCoefficientFactor.Mul(maxCoefficientFactor, d.d10, -1)
	maxCoefficientFactorInt := maxCoefficientFactor.Big()

	poly := make([]*saferith.Nat, d.t)
	poly[0] = new(saferith.Nat).Mul(d.d2, value, -1)
	for i := uint(1); i < d.t; i++ {
		cInt, err := crand.Int(prng, maxCoefficientFactorInt)
		if err != nil {
			return nil, errs.WrapRandomSample(err, "cannot sample")
		}
		c := new(saferith.Nat).SetBig(cInt, maxCoefficientFactor.AnnouncedLen())
		poly[i] = new(saferith.Nat).Mul(c, d.d, -1)
	}

	shares := make([]*Share, d.n)
	for i := uint(0); i < d.n; i++ {
		id := i + 1
		v := eval(poly, id)
		shares[i] = &Share{
			Id:    types.SharingID(id),
			Value: v,
		}
	}

	return shares, nil
}

func (d *Dealer) Combine(shares []*Share) *saferith.Nat {
	pos := new(saferith.Nat).SetUint64(0).Resize(0)
	neg := new(saferith.Nat).SetUint64(0).Resize(0)

	for _, shareJ := range shares {
		x := d.delta
		j := int64(shareJ.Id)
		for _, shareI := range shares {
			i := int64(shareI.Id)
			if i == j {
				continue
			}
			x *= i
			x /= i - j
		}

		println("combine ", x, hex.EncodeToString(shareJ.Value.Big().Bytes()))

		if x >= 0 {
			xNat := new(saferith.Nat).SetUint64(uint64(x))
			xNat.Resize(xNat.TrueLen())
			l := new(saferith.Nat).Mul(shareJ.Value, xNat, -1)
			pos.Add(pos, l, -1)
		} else {
			xNat := new(saferith.Nat).SetUint64(uint64(-x))
			xNat.Resize(xNat.TrueLen())
			l := new(saferith.Nat).Mul(shareJ.Value, xNat, -1)
			neg.Add(neg, l, -1)
		}
	}

	println("combine pos", hex.EncodeToString(pos.Big().Bytes()))
	println("combine neg", hex.EncodeToString(neg.Big().Bytes()))
	println("combine d3", hex.EncodeToString(d.d3.Big().Bytes()))

	vv := new(saferith.Nat).Sub(pos, neg, -1)
	v := new(saferith.Nat).Div(vv, saferith.ModulusFromNat(d.d3), -1)
	return v
}

func (d *Dealer) precompute() {
	delta := int64(1)
	for i := int64(2); i <= int64(d.n); i++ {
		delta *= i
	}
	dNat := new(saferith.Nat).SetUint64(uint64(delta))
	// dNat.Resize(dNat.TrueLen())
	d2 := new(saferith.Nat).Mul(dNat, dNat, -1)
	// d2.Resize(dNat.TrueLen())
	d3 := new(saferith.Nat).Mul(dNat, d2, -1)
	// d3.Resize(d3.TrueLen())
	d4 := new(saferith.Nat).Mul(d2, d2, -1)
	d8 := new(saferith.Nat).Mul(d4, d4, -1)
	d10 := new(saferith.Nat).Mul(d8, d2, -1)
	// d10.Resize(d10.TrueLen())

	d.delta = delta
	d.d = dNat
	d.d2 = d2
	d.d3 = d3
	d.d10 = d10
}

func eval(poly []*saferith.Nat, at uint) *saferith.Nat {
	atNat := new(saferith.Nat).SetUint64(uint64(at))
	atNat.Resize(atNat.TrueLen())
	val := new(saferith.Nat).SetUint64(0).Resize(0)
	for i := int64(len(poly) - 1); i >= 0; i-- {
		val.Mul(val, atNat, -1)
		val.Add(val, poly[i], -1)
	}

	return val
}
