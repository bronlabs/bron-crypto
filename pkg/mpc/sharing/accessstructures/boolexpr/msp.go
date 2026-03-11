package boolexpr

import (
	"slices"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/mat"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/internal"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw/msp"
)

func InducedMSP[E algebra.PrimeFieldElement[E]](f algebra.PrimeField[E], ac *ThresholdGateAccessStructure) (*msp.MSP[E], error) {
	m, rho, err := convert(f, ac)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to convert the access structure to an MSP matrix")
	}

	mspRho := make(map[int]internal.ID)
	for i, id := range rho {
		mspRho[i] = id
	}

	inducedMsp, err := msp.NewStandardMSP(m, mspRho)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create an MSP from the MSP matrix")
	}
	return inducedMsp, nil
}

func convert[F algebra.PrimeFieldElement[F]](field algebra.PrimeField[F], as *ThresholdGateAccessStructure) (*mat.Matrix[F], []internal.ID, error) {
	leaves := as.CountLeaves()
	idx := func(r, c int) int { return r*leaves + c }

	bigM := make([]F, leaves*leaves)
	for i := range bigM {
		bigM[i] = field.Zero()
	}
	bigM[0] = field.One()

	l := make([]*Node, leaves)
	l[0] = as.root
	m := 1
	d := 1
	z := 0

	for z >= 0 {
		z = -1
		for i := range m {
			if l[i].kind == gate {
				z = i
				break
			}
		}
		if z >= 0 {
			bigM1 := slices.Clone(bigM)
			l1 := slices.Clone(l)
			m1 := m
			d1 := d

			fz := l[z]
			m2 := len(fz.children)
			d2 := fz.threshold

			for i := range z {
				l[i] = l1[i]
				for j := range d1 {
					bigM[idx(i, j)] = bigM1[idx(i, j)]
				}
				for j := d1; j < d1+d2-1; j++ {
					bigM[idx(i, j)] = field.Zero()
				}
			}
			for i := z; i < z+m2; i++ {
				l[i] = fz.children[i-z]
				for j := range d1 {
					bigM[idx(i, j)] = bigM1[idx(z, j)]
				}
				x := field.FromUint64(uint64(i)).Sub(field.FromUint64(uint64(z))).Add(field.One())
				a := x.Clone()
				for j := d1; j < d1+d2-1; j++ {
					bigM[idx(i, j)] = x
					x = x.Mul(a)
				}
			}
			for i := z + m2; i < m1+m2-1; i++ {
				l[i] = l1[i-m2+1]
				for j := range d1 {
					bigM[idx(i, j)] = bigM1[idx(i-m2+1, j)]
				}
				for j := d1; j < d1+d2-1; j++ {
					bigM[idx(i, j)] = field.Zero()
				}
			}
			m = m1 + m2 - 1
			d = d1 + d2 - 1
		}
	}

	matrices, err := mat.NewMatrixModule(uint(leaves), uint(leaves), field)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("failed to create a matrix module")
	}
	resultM, err := matrices.NewRowMajor(bigM...)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("failed to create a matrix")
	}
	resultM, err = resultM.RowSlice(0, m)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("failed to get the first m rows")
	}
	resultM, err = resultM.ColumnSlice(0, d)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("failed to get the first d columns")
	}

	resultRho := make([]internal.ID, len(l))
	for i, li := range l {
		if li.kind != attribute {
			return nil, nil, internal.ErrFailed.WithMessage("internal error")
		}
		resultRho[i] = li.attr
	}

	return resultM, resultRho, nil
}
