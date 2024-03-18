package impl

import (
	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils"
)

var (
	C1   = new(saferith.Nat).SetBytes(utils.DecodeString("0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe"))
	C2   = new(saferith.Nat).SetBytes(utils.DecodeString("2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b1"))
	C3   = new(saferith.Nat).SetBytes(utils.DecodeString("2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0"))
	C4   = new(saferith.Nat).SetBytes(utils.DecodeString("0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd"))
	C1ed = new(saferith.Nat).SetBytes(utils.DecodeString("0f26edf460a006bbd27b08dc03fc4f7ec5a1d3d14b7d1a82cc6e04aaff457e06"))
	J    = new(saferith.Nat).SetBytes(utils.DecodeString("0000000000000000000000000000000000000000000000000000000000076d06"))
)

type Elligator2Params struct {
	c1, c2, c3, c4, c1ed, J curves.BaseFieldElement
}

// NewElligator2Parameters returns the parameters for the Elligator2 map for curve25519
// and edwards25519, as described in https://datatracker.ietf.org/doc/html/rfc9380#Appendix-G.2
func NewElligator2Params(curve curves.Curve, useHardcoded bool) *Elligator2Params {
	if useHardcoded {
		return &Elligator2Params{
			c1:   curve.BaseField().Element().SetNat(C1),
			c2:   curve.BaseField().Element().SetNat(C2),
			c3:   curve.BaseField().Element().SetNat(C3),
			c4:   curve.BaseField().Element().SetNat(C4),
			c1ed: curve.BaseField().Element().SetNat(C1ed),
			J:    curve.BaseField().Element().SetNat(J),
		}
	}
	saferithArith := new(saferith.Nat)
	q := curve.BaseField().Order().Nat()

	// c1 = (q + 3) / 8
	threeNat := new(saferith.Nat).SetUint64(3)
	eightMod := saferith.ModulusFromUint64(8)
	c1Nat := saferithArith.Div(saferithArith.Add(q, threeNat, -1), eightMod, -1)
	c1 := curve.BaseField().Element().SetNat(c1Nat)

	// c2 = 2^c1
	two := curve.BaseField().New(2)
	c2 := two.Exp(c1)

	// c3 = sqrt(-1)
	oneNat := new(saferith.Nat).SetUint64(1)
	c3, err := curve.BaseField().Element().SetNat(saferithArith.Sub(q, oneNat, -1)).Sqrt()
	if err != nil {
		panic("sqrt(-1) does not exist for c3 in Elligator2")
	}

	// c4 = (q-5)
	fiveNat := new(saferith.Nat).SetUint64(5)
	c4Nat := saferithArith.Div(saferithArith.Sub(q, fiveNat, -1), eightMod, -1)
	c4 := curve.BaseField().Element().SetNat(c4Nat)

	// J = 486662
	J := curve.BaseField().New(486662)

	// c1ed = sqrt(-486664)
	c1ed, err := curve.BaseField().Zero().Sub(curve.BaseField().New(486664)).Sqrt()
	if err != nil || c1ed.IsOdd() { // sgn0(c1ed) MUST equal 0
		panic("sqrt(-486664) does not exist for c1ed in Elligator2")
	}

	return &Elligator2Params{c1, c2, c3, c4, c1ed, J}
}

func (el2 *Elligator2Params) MapToCurveElligator2Curve25519(u curves.BaseFieldElement) (xn, xd, y, z curves.BaseFieldElement) {
	F := u.BaseField()
	tv1 := u.Square()                                     /*  1 */
	tv1 = F.New(2).Mul(tv1)                               /*  2 */
	xd = tv1.Add(F.One())                                 /*  3 */
	x1n := el2.J.Neg()                                    /*  4 */
	tv2 := xd.Square()                                    /*  5 */
	gxd := tv2.Mul(xd)                                    /*  6 */
	gx1 := el2.J.Mul(tv1)                                 /*  7 */
	gx1 = gx1.Mul(x1n)                                    /*  8 */
	gx1 = gx1.Add(tv2)                                    /*  9 */
	gx1 = gx1.Mul(x1n)                                    /* 10 */
	tv3 := gxd.Square()                                   /* 11 */
	tv2 = tv3.Square()                                    /* 12 */
	tv3 = tv3.Mul(gxd)                                    /* 13 */
	tv3 = tv3.Mul(gx1)                                    /* 14 */
	tv2 = tv2.Mul(tv3)                                    /* 15 */
	y11 := tv2.Exp(el2.c4)                                /* 16 */
	y11 = y11.Mul(tv3)                                    /* 17 */
	y12 := y11.Mul(el2.c3)                                /* 18 */
	tv2 = y11.Square()                                    /* 19 */
	tv2 = tv2.Mul(gxd)                                    /* 20 */
	e1 := tv2.Equal(gx1)                                  /* 21 */
	y1 := F.Select(utils.BoolTo[int](e1), y12, y11)       /* 22 */
	x2n := x1n.Mul(tv1)                                   /* 23 */
	y21 := y11.Mul(u)                                     /* 24 */
	y21 = y21.Mul(el2.c2)                                 /* 25 */
	y22 := y21.Mul(el2.c3)                                /* 26 */
	gx2 := gx1.Mul(tv1)                                   /* 27 */
	tv2 = y21.Square()                                    /* 28 */
	tv2 = tv2.Mul(gxd)                                    /* 29 */
	e2 := tv2.Equal(gx2)                                  /* 30 */
	y2 := F.Select(utils.BoolTo[int](e2), y22, y21)       /* 31 */
	tv2 = y1.Square()                                     /* 32 */
	tv2 = tv2.Mul(gxd)                                    /* 33 */
	e3 := tv2.Equal(gx1)                                  /* 34 */
	xn = F.Select(utils.BoolTo[int](e3), x2n, x1n)        /* 35 */
	y = F.Select(utils.BoolTo[int](e3), y2, y1)           /* 36 */
	e4 := y.IsOdd()                                       /* 37 */
	y = F.Select(utils.BoolTo[int](e3 != e4), y, y.Neg()) /* 38 */
	return xn, xd, y, F.One()
}

func (el2 *Elligator2Params) MapToCurveElligator2edwards25519(u curves.BaseFieldElement) (xn, xd, yn, yd curves.BaseFieldElement) {
	F := u.BaseField()
	xMn, xMd, yMn, yMd := el2.MapToCurveElligator2Curve25519(u) /*  1 */
	xn = xMn.Mul(yMd)                                           /*  2 */
	xn = xn.Mul(el2.c1ed)                                       /*  3 */
	xd = xMd.Mul(yMn)                                           /*  4 */
	yn = xMn.Sub(xMd)                                           /*  5 */
	yd = xMn.Add(xMd)                                           /*  6 */
	tv1 := xd.Mul(yd)                                           /*  7 */
	e := tv1.IsZero()                                           /*  8 */
	xn = F.Select(utils.BoolTo[int](e), xn, F.Zero())           /*  9 */
	xd = F.Select(utils.BoolTo[int](e), xd, F.One())            /* 10 */
	yn = F.Select(utils.BoolTo[int](e), yn, F.One())            /* 11 */
	yd = F.Select(utils.BoolTo[int](e), yd, F.One())            /* 12 */
	return xn, xd, yn, yd                                       /* 13 */
}
