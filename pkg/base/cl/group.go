package cl

import (
	"math/big"
)

type ClassGroup struct {
	Discriminant *big.Int
}

func NewClassGroup(discriminant *big.Int) *ClassGroup {
	if discriminant.Sign() >= 0 || (discriminant.Bits()[0]%4 != 0 && discriminant.Bits()[0]%4 != 3) {
		panic("invalid discriminant")
	}

	return &ClassGroup{
		Discriminant: discriminant,
	}
}

func (g *ClassGroup) Identity() *ClassGroupElement {
	d := new(big.Int).Neg(g.Discriminant)
	if d.Bit(0) != 0 {
		return &ClassGroupElement{
			A: new(big.Int).SetUint64(1),
			B: new(big.Int).SetUint64(1),
			C: new(big.Int).Rsh(new(big.Int).Add(d, new(big.Int).SetUint64(1)), 2),
		}
	} else {
		return &ClassGroupElement{
			A: new(big.Int).SetUint64(1),
			B: new(big.Int).SetUint64(0),
			C: new(big.Int).Rsh(d, 2),
		}
	}
}

type ClassGroupElement struct {
	A, B, C *big.Int
}

func (g *ClassGroupElement) reduce() *ClassGroupElement {
	return g
}
