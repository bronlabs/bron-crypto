package boolexpr

import (
	"slices"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/mat"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/internal"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw/msp"
)

// InducedMSP constructs a monotone span programme induced by a threshold-gate
// access tree.
//
// The construction follows Algorithm 1 of Liu, Cao, and Wong (ePrint
// 2010/374): each threshold gate is expanded into a local Vandermonde-style
// block, and the resulting matrix has one row per attribute leaf.
func InducedMSP[E algebra.PrimeFieldElement[E]](f algebra.PrimeField[E], ac *ThresholdGateAccessStructure) (*msp.MSP[E], error) {
	m, rho, err := convert(f, ac)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to convert the access structure to an MSP matrix")
	}

	mspRho := make(map[int]internal.ID)
	for i, id := range rho {
		mspRho[i] = id
	}

	inducedMsp, err := msp.NewMSP(m, mspRho)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create an MSP from the MSP matrix")
	}
	return inducedMsp, nil
}

func convert[F algebra.PrimeFieldElement[F]](field algebra.PrimeField[F], as *ThresholdGateAccessStructure) (*mat.Matrix[F], []internal.ID, error) {
	leaves := as.CountLeaves()
	idx := func(r, c int) int { return r*leaves + c }

	// The code has references to the paper's "Algorithm 1: Convert" steps.
	// note: Go code is 0-indexed unlike paper's algorithm (which is 1-indexed) hence off-by-one discrepancies.
	// step 1
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

	// step 2
	for z >= 0 {
		// step 2
		z = -1

		// steps 4-9
		for i := range m {
			if l[i].kind == gate {
				z = i
				break
			}
		}

		// step 10
		if z >= 0 {
			// step 14
			bigM1 := slices.Clone(bigM)
			l1 := slices.Clone(l)
			m1 := m
			d1 := d

			// steps 11-13
			fz := l[z]
			m2 := len(fz.children)
			d2 := fz.threshold

			// step 15
			for i := range z {
				// step 16
				l[i] = l1[i]

				// steps 17
				for j := range d1 {
					// step 18
					bigM[idx(i, j)] = bigM1[idx(i, j)]
				}

				// steps 20
				for j := d1; j < d1+d2-1; j++ {
					// step 21
					bigM[idx(i, j)] = field.Zero()
				}
			}

			// step 24
			for i := z; i < z+m2; i++ {
				// step 25
				l[i] = fz.children[i-z]

				// steps 26
				for j := range d1 {
					// step 27
					bigM[idx(i, j)] = bigM1[idx(z, j)]
				}

				// step 29
				x := field.FromUint64(uint64(i)).Sub(field.FromUint64(uint64(z))).Add(field.One())
				a := x.Clone()

				// steps 30
				for j := d1; j < d1+d2-1; j++ {
					// step 31
					bigM[idx(i, j)] = x

					// step 32
					x = x.Mul(a)
				}
			}

			// step 35
			for i := z + m2; i < m1+m2-1; i++ {
				// step 36
				l[i] = l1[i-m2+1]

				// step 37
				for j := range d1 {
					// step 38
					bigM[idx(i, j)] = bigM1[idx(i-m2+1, j)]
				}

				// step 40
				for j := d1; j < d1+d2-1; j++ {
					// step 41
					bigM[idx(i, j)] = field.Zero()
				}
			}

			// step 44
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
