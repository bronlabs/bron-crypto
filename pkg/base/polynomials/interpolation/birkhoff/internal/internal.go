package internal

import (
	"sort"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
)

type Node[F algebra.PrimeFieldElement[F], G any] struct {
	X F
	J uint64
	Y G
}

type Nodes[F algebra.PrimeFieldElement[F], G any] []*Node[F, G]

func (n Nodes[F, G]) Len() int {
	return len(n)
}

func (n Nodes[F, G]) Less(i, j int) bool {
	xi, err := num.N().FromCardinal(n[i].X.Cardinal())
	if err != nil {
		panic("birkhoff: could not convert cardinal to natural number: " + err.Error())
	}
	xj, err := num.N().FromCardinal(n[j].X.Cardinal())
	if err != nil {
		panic("birkhoff: could not convert cardinal to natural number: " + err.Error())
	}
	if xi.Compare(xj) < 0 {
		return true
	}
	if xi.Compare(xj) > 0 {
		return false
	}

	return n[i].J < n[j].J
}

func (n Nodes[F, G]) Swap(i, j int) {
	n[i], n[j] = n[j], n[i]
}

func SortNodes[F algebra.PrimeFieldElement[F], G any](xs []F, js []uint64, ys []G) (xsOut []F, jsOut []uint64, ysOut []G) {
	nodes := make([]*Node[F, G], 0, len(xs))
	for i := range xs {
		nodes = append(nodes, &Node[F, G]{
			X: xs[i],
			J: js[i],
			Y: ys[i],
		})
	}
	sort.Sort(Nodes[F, G](nodes))
	xsOut = sliceutils.Map(nodes, func(n *Node[F, G]) F { return n.X })
	jsOut = sliceutils.Map(nodes, func(n *Node[F, G]) uint64 { return n.J })
	ysOut = sliceutils.Map(nodes, func(n *Node[F, G]) G { return n.Y })
	return xsOut, jsOut, ysOut
}

func Phi[F algebra.PrimeFieldElement[F]](t int, i F, j uint64) (F, error) {
	field := algebra.StructureMustBeAs[algebra.PrimeField[F]](i.Structure())
	coeffs := make([]F, t+1)
	for c := range coeffs {
		coeffs[c] = field.Zero()
	}
	coeffs[len(coeffs)-1] = field.One()
	polys, err := polynomials.NewPolynomialRing(field)
	if err != nil {
		return *new(F), errs.Wrap(err).WithMessage("could not create polynomial ring")
	}
	poly, err := polys.New(coeffs...)
	if err != nil {
		return *new(F), errs.Wrap(err).WithMessage("could not create polynomial")
	}
	for range j {
		poly = poly.Derivative()
	}

	return poly.Eval(i), nil
}
