package kuiper

import (
	"fmt"
	"reflect"
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	bls12381impl "github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381/impl"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

const Name = "BLS12381"

var (
	kuiperInitOnce sync.Once
	pcInstance     PairingCurve

	p               = bls12381impl.FpModulus
	r               = bls12381impl.FqModulus
	embeddingDegree = new(saferith.Nat).SetUint64(12)
)

type SourceSubGroups interface {
	PlutoCurve | TritonCurve
}

func GetSourceSubGroup[S SourceSubGroups]() curves.Curve {
	s := new(S)
	name := reflect.TypeOf(s).Elem().Name()
	switch name {
	case "G1":
		return NewG1()
	case "G2":
		return NewG2()
	default:
		panic(fmt.Sprintf("name %s is not supported", name))
	}
}

func InCorrectSubGroup[S SourceSubGroups](p curves.PairingPoint) bool {
	return GetSourceSubGroup[S]().Name() == p.Curve().Name()
}

var _ curves.PairingCurve = (*PairingCurve)(nil)

type PairingCurve struct {
	_ ds.Incomparable
}

func pcInit() {
	pcInstance = PairingCurve{}
}

func NewPairingCurve() *PairingCurve {
	kuiperInitOnce.Do(pcInit)
	return &pcInstance
}

func (*PairingCurve) Name() string {
	return Name
}

func (*PairingCurve) EmbeddingDegree() *saferith.Nat {
	return embeddingDegree
}

func (*PairingCurve) G1() curves.Curve {
	return NewG1()
}

func (*PairingCurve) G2() curves.Curve {
	return NewG2()
}

func (*PairingCurve) Gt() curves.Gt {
	return NewGt()
}

func (*PairingCurve) Pair(pG1, pG2 curves.PairingPoint) (curves.GtMember, error) {
	p1, ok := pG1.(*PointG1)
	if !ok {
		return nil, errs.NewType("first point is not in G1")
	}
	p2, ok := pG2.(*PointG2)
	if !ok {
		return nil, errs.NewType("second point is not in G2")
	}
	return p1.Pair(p2), nil
}

func (*PairingCurve) MultiPair(points ...curves.PairingPoint) (curves.GtMember, error) {
	if len(points)%2 != 0 {
		return nil, errs.NewLength("#G1 != #G2")
	}
	eng := new(bls12381impl.Engine)
	for i := 0; i < len(points); i += 2 {
		pt1, ok := points[i].(*PointG1)
		if !ok {
			return nil, errs.NewType("point %d is not in G1", i)
		}
		pt2, ok := points[i+1].(*PointG2)
		if !ok {
			return nil, errs.NewType("point %d is not G2", i+1)
		}
		eng.AddPair(pt1.V, pt2.V)
	}
	value := eng.Result()
	return &GtMember{V: value}, nil
}
