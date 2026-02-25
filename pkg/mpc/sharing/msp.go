package sharing

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/mat"
	"github.com/bronlabs/errs-go/errs"
)

func NewMSP[E algebra.FiniteFieldElement[E]](m *mat.Matrix[E], psi map[int]ID) (*MSP[E], error) {
	if m == nil {
		return nil, ErrIsNil.WithMessage("matrix cannot be nil")
	}
	if psi == nil {
		return nil, ErrIsNil.WithMessage("psi mapping cannot be nil")
	}

	rows, cols := m.Dimensions()
	if rows <= 0 || cols <= 0 {
		return nil, ErrValue.WithMessage("matrix must have positive dimensions, got %d x %d", rows, cols)
	}

	targetVectorElements := make([]E, cols)
	targetVectorElements[0] = m.Module().ScalarRing().One()
	for i := 1; i < cols; i++ {
		targetVectorElements[i] = m.Module().ScalarRing().Zero()
	}
	rowVectorSpace, err := mat.NewMatrixModule(1, uint(cols), m.Module().ScalarRing())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create vector module")
	}
	targetVector, err := rowVectorSpace.NewRowMajor(targetVectorElements...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create target vector")
	}

	// Require psi defined for every row index 0..rows-1
	for i := range rows {
		if _, ok := psi[i]; !ok {
			return nil, ErrValue.WithMessage("psi must contain an entry for each row index: missing index %d", i)
		}
	}

	// Reject extra indices (helps catch subtle bugs)
	for k, v := range psi {
		if k < 0 || k >= rows {
			return nil, ErrValue.WithMessage("psi contains out-of-range row index %d (rows=%d)", k, rows)
		}
		if v == 0 {
			return nil, ErrValue.WithMessage("psi cannot map to zero ID for row index %d", k)
		}
	}

	psiInv := make(map[ID][]int)
	for rowIndex, id := range psi {
		if _, exists := psiInv[id]; !exists {
			psiInv[id] = []int{rowIndex}
		} else {
			psiInv[id] = append(psiInv[id], rowIndex)
		}
	}

	return &MSP[E]{
		matrix:          m.Clone(),
		psi:             hashmap.NewComparableFromNativeLike(psi).Freeze(),
		psiInv:          psiInv,
		targetRowVector: targetVector,
	}, nil
}

type MSP[E algebra.FiniteFieldElement[E]] struct {
	matrix          *mat.Matrix[E]
	psi             ds.Map[int, ID]
	psiInv          map[ID][]int
	targetRowVector *mat.Matrix[E]
}

func (m *MSP[E]) Matrix() *mat.Matrix[E] {
	return m.matrix
}

func (m *MSP[E]) Psi() ds.Map[int, ID] {
	return m.psi
}

func (m *MSP[E]) TargetVector() *mat.Matrix[E] {
	return m.targetRowVector
}

func (m *MSP[E]) Size() int {
	rows, _ := m.matrix.Dimensions()
	return rows
}

func (m *MSP[E]) D() int {
	_, cols := m.matrix.Dimensions()
	return cols
}

func (m *MSP[E]) ReconstructionVector(IDs ...ID) (*mat.Matrix[E], error) {
	idSet := hashset.NewComparable(IDs...)
	rows := make([]int, 0, m.psi.Size())
	for id := range idSet.Iter() {
		rowsID, ok := m.psiInv[id]
		if !ok {
			return nil, ErrValue.WithMessage("ID %d is not associated with any row in the MSP", id)
		}
		rows = append(rows, rowsID...)
	}
	if len(rows) == 0 {
		return nil, ErrValue.WithMessage("no rows selected for given IDs")
	}
	MIDs, err := m.matrix.SubMatrixGivenRows(rows...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to extract submatrix for given IDs")
	}
	out, err := mat.SolveLeft(MIDs, m.targetRowVector)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("target vector is not in the span of the selected rows")
	}
	return out, nil
}

func (m *MSP[E]) Accepts(IDs ...ID) bool {
	_, err := m.ReconstructionVector(IDs...)
	return err == nil
}
