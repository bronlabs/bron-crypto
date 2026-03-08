package msp

import (
	"maps"
	"slices"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/mat"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/iterutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/internal"
)

// ID uniquely identifies a shareholder.
type ID = internal.ID

// NewStandardMSP constructs an MSP with the standard target vector e_0 = (1,0,...,0).
func NewStandardMSP[E algebra.FiniteFieldElement[E]](m *mat.Matrix[E], rowsToHolders map[int]ID) (*MSP[E], error) {
	if m == nil {
		return nil, ErrIsNil.WithMessage("matrix cannot be nil")
	}
	targetVector, err := m.Module().NewStandardUnit(0)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create target vector")
	}
	out, err := NewMSP(m, rowsToHolders, targetVector)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create MSP")
	}
	return out, nil
}

// NewMSP constructs a monotone span programme from a matrix, a row-to-holder
// labelling, and an explicit target vector.
func NewMSP[E algebra.FiniteFieldElement[E]](m *mat.Matrix[E], rowsToHolders map[int]ID, targetVector *mat.Matrix[E]) (*MSP[E], error) {
	if m == nil {
		return nil, ErrIsNil.WithMessage("matrix cannot be nil")
	}
	if rowsToHolders == nil {
		return nil, ErrIsNil.WithMessage("rowsToHolders mapping cannot be nil")
	}
	if targetVector == nil {
		return nil, ErrIsNil.WithMessage("target vector cannot be nil")
	}
	if !targetVector.IsRowVector() {
		return nil, ErrValue.WithMessage("target vector must be a row vector")
	}

	rows, cols := m.Dimensions()
	_, targetCols := targetVector.Dimensions()
	if targetCols != cols {
		return nil, ErrValue.WithMessage("target vector length must match number of columns in matrix: got %d, expected %d", targetCols, cols)
	}

	// Require labels defined for every row index 0..rows-1
	for i := range rows {
		if _, ok := rowsToHolders[i]; !ok {
			return nil, ErrValue.WithMessage("rowsToHolders must contain an entry for each row index: missing index %d", i)
		}
	}

	// Reject extra indices (helps catch subtle bugs)
	for k, v := range rowsToHolders {
		if k < 0 || k >= rows {
			return nil, ErrValue.WithMessage("rowsToHolders contains out-of-range row index %d (rows=%d)", k, rows)
		}
		if v == 0 {
			return nil, ErrValue.WithMessage("rowsToHolders cannot map to zero ID for row index %d", k)
		}
	}

	holdersToRows := make(map[ID][]int)
	for rowIndex, id := range rowsToHolders {
		if _, exists := holdersToRows[id]; !exists {
			holdersToRows[id] = []int{rowIndex}
		} else {
			holdersToRows[id] = append(holdersToRows[id], rowIndex)
		}
	}

	return &MSP[E]{
		matrix:          m.Clone(),
		rowsToHolders:   rowsToHolders,
		holdersToRows:   holdersToRows,
		targetRowVector: targetVector,
		f:               algebra.StructureMustBeAs[algebra.FiniteField[E]](m.Module().ScalarStructure()),
	}, nil
}

// MSP is a monotone span programme over a finite field. It encodes a monotone
// access structure via a matrix M, a target vector t, and a labelling of rows
// to shareholder IDs.
type MSP[E algebra.FiniteFieldElement[E]] struct {
	matrix          *mat.Matrix[E]
	rowsToHolders   map[int]ID
	holdersToRows   map[ID][]int
	targetRowVector *mat.Matrix[E]
	f               algebra.FiniteField[E]
}

// Matrix returns the MSP matrix.
func (m *MSP[E]) Matrix() *mat.Matrix[E] {
	return m.matrix
}

// BaseField returns the finite field over which the MSP is defined.
func (m *MSP[E]) BaseField() algebra.FiniteField[E] {
	return m.f
}

// RowsToHolders returns a copy of the mapping from matrix row indices to shareholder IDs.
func (m *MSP[E]) RowsToHolders() map[int]ID {
	return maps.Clone(m.rowsToHolders)
}

// HoldersToRows returns a copy of the reverse mapping from shareholder IDs to their row indices.
func (m *MSP[E]) HoldersToRows() map[ID][]int {
	return maps.Clone(m.holdersToRows)
}

// TargetVector returns the target row vector of the MSP.
func (m *MSP[E]) TargetVector() *mat.Matrix[E] {
	return m.targetRowVector
}

// Size returns the number of rows in the MSP matrix.
func (m *MSP[E]) Size() uint {
	rows, _ := m.matrix.Dimensions()
	return uint(rows)
}

// D returns the number of columns in the MSP matrix.
func (m *MSP[E]) D() uint {
	_, cols := m.matrix.Dimensions()
	return uint(cols)
}

// IsIdeal reports whether the MSP assigns exactly one row to each shareholder.
func (m *MSP[E]) IsIdeal() bool {
	return iterutils.All(maps.Values(m.holdersToRows), func(rows []int) bool { return len(rows) == 1 })
}

// ReconstructionVector computes the linear combination coefficients that
// express the target vector as a combination of the rows belonging to the
// given shareholder IDs. The returned coefficients are ordered by ascending
// matrix row index. Returns an error if the IDs do not form a qualified set.
func (m *MSP[E]) ReconstructionVector(IDs ...ID) (*mat.Matrix[E], error) {
	idSet := hashset.NewComparable(IDs...)
	sortedIDs := idSet.List()
	slices.Sort(sortedIDs)
	rows := make([]int, 0, len(m.holdersToRows))
	for _, id := range sortedIDs {
		rowsID, ok := m.holdersToRows[id]
		if !ok {
			return nil, ErrValue.WithMessage("ID %d is not associated with any row in the MSP", id)
		}
		rows = append(rows, rowsID...)
	}
	if len(rows) == 0 {
		return nil, ErrValue.WithMessage("no rows selected for given IDs")
	}
	slices.Sort(rows)
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

// Accepts reports whether the given shareholder IDs form a qualified set.
func (m *MSP[E]) Accepts(IDs ...ID) bool {
	_, err := m.ReconstructionVector(IDs...)
	return err == nil
}

var (
	// ErrValue indicates an invalid value.
	ErrValue = internal.ErrValue
	// ErrIsNil indicates a required value was nil.
	ErrIsNil = internal.ErrIsNil
)
