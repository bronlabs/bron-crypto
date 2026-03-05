package internal

import (
	"sort"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/errs-go/errs"
)

type Node[F algebra.PrimeFieldElement[F]] struct {
	X F
	J uint64
	Y F
}

type Nodes[F algebra.PrimeFieldElement[F]] []*Node[F]

func (n Nodes[F]) Len() int {
	return len(n)
}

func (n Nodes[F]) Less(i, j int) bool {
	xi, _ := num.N().FromBytesBE(n[i].X.Cardinal().BytesBE())
	xj, _ := num.N().FromBytesBE(n[j].X.Cardinal().BytesBE())
	if xi.Compare(xj) < 0 {
		return true
	}
	if xi.Compare(xj) > 0 {
		return false
	}

	return n[i].J < n[j].J
}

func (n Nodes[F]) Swap(i, j int) {
	n[i], n[j] = n[j], n[i]
}

func SortNodes[F algebra.PrimeFieldElement[F]](xs []F, js []uint64, ys []F) (xsOut []F, jsOut []uint64, ysOut []F) {
	nodes := make([]*Node[F], 0, len(xs))
	for i := range xs {
		nodes = append(nodes, &Node[F]{
			X: xs[i],
			J: js[i],
			Y: ys[i],
		})
	}
	sort.Sort(Nodes[F](nodes))
	xsOut = sliceutils.Map(nodes, func(n *Node[F]) F { return n.X })
	jsOut = sliceutils.Map(nodes, func(n *Node[F]) uint64 { return n.J })
	ysOut = sliceutils.Map(nodes, func(n *Node[F]) F { return n.Y })
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
