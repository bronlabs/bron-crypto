package mat

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/errs-go/errs"
)

// SolveRight solves M*x = b where M is this m×n matrix and b is column (length m).
// Returns x as an n×1 rectangular matrix, or an error if the system is inconsistent.
// Free variables (in underdetermined systems) are set to zero.
func SolveRight[S algebra.FiniteFieldElement[S]](m, column *Matrix[S]) (*Matrix[S], error) {
	if column.cols() != 1 {
		return nil, ErrDimension.WithMessage("input must be a column vector (1 column), got %d columns", column.cols())
	}
	if column.rows() != m.m {
		return nil, ErrDimension.WithMessage("column length %d does not match matrix row count %d", column.rows(), m.m)
	}

	// Build column vector as an m×1 rectangular matrix and augment [M | b].
	aug, err := m.Augment(column)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to build augmented matrix for SolveRight")
	}

	field, err := algebra.StructureAs[algebra.FiniteField[S]](m.Module().ScalarStructure())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("matrix scalar structure is not a field")
	}

	sol, err := solveAugmented(field, aug)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("column is not in the span of the matrix")
	}

	solutionSpace, err := NewMatrixModule(uint(m.n), 1, field)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create solution space matrix module")
	}
	out, err := solutionSpace.NewRowMajor(sol...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create solution matrix from row-major data")
	}
	return out, nil
}

// SolveLeft solves x*M = r where M is this m×n matrix and r is row (length n).
// This is equivalent to solving M^T * x^T = r^T.
// Returns x as an m×1 rectangular matrix, or an error if the system is inconsistent.
func SolveLeft[S algebra.FiniteFieldElement[S]](m, row *Matrix[S]) (*Matrix[S], error) {
	if row.rows() != 1 {
		return nil, ErrDimension.WithMessage("input must be a row vector (1 row), got %d rows", row.rows())
	}
	if row.cols() != m.n {
		return nil, ErrDimension.WithMessage("row length %d does not match matrix column count %d", row.cols(), m.n)
	}

	// Build augmented matrix [M^T | r^T] in place (n×(m+1)).
	// Column j of aug = row j of M for j<m, column m = r^T.
	var aug Matrix[S]
	aug.init(m.n, m.m+1)
	d := aug.data()
	mData := m.data()
	rData := row.data()
	for i := range m.n {
		for j := range m.m {
			d[aug.idx(i, j)] = mData[m.idx(j, i)]
		}
		d[aug.idx(i, m.m)] = rData[i]
	}

	field, err := algebra.StructureAs[algebra.FiniteField[S]](m.Module().ScalarStructure())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("matrix scalar structure is not a field")
	}

	sol, err := solveAugmented(field, &aug)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("row is not in the row span of the matrix")
	}

	solutionSpace, err := NewMatrixModule(uint(m.m), 1, field)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create solution space matrix module")
	}
	out, err := solutionSpace.NewRowMajor(sol...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create solution matrix from row-major data")
	}
	return out, nil
}

// solveAugmented performs Gauss-Jordan elimination in place on aug, treating
// the last column as the augmented vector b in [A | b]. It returns the solution
// as a slice of length (cols-1), or an error if the system is inconsistent.
// Free variables are set to zero. aug is modified in place.
func solveAugmented[S algebra.FiniteFieldElement[S]](field algebra.Field[S], aug matrixWrapper[S]) ([]S, error) {
	rows, cols := aug.rows(), aug.cols()
	numVars := cols - 1
	d := aug.data()

	pivotCols := make([]int, 0, min(rows, numVars))
	pivotRow := 0

	for pc := 0; pc < numVars && pivotRow < rows; pc++ {
		// Find pivot.
		pr := -1
		for r := pivotRow; r < rows; r++ {
			if !d[aug.idx(r, pc)].IsZero() {
				pr = r
				break
			}
		}
		if pr < 0 {
			continue // free variable
		}

		// Swap rows.
		if pr != pivotRow {
			for j := range cols {
				pi, ri := aug.idx(pivotRow, j), aug.idx(pr, j)
				d[pi], d[ri] = d[ri], d[pi]
			}
		}

		// Scale pivot row so the leading entry becomes 1.
		invPivot, err := d[aug.idx(pivotRow, pc)].TryInv()
		if err != nil {
			return nil, ErrFailed.WithMessage("pivot element is not invertible")
		}
		for j := range cols {
			idx := aug.idx(pivotRow, j)
			d[idx] = d[idx].Mul(invPivot)
		}

		// Eliminate this column from all other rows.
		for i := range rows {
			if i == pivotRow {
				continue
			}
			factor := d[aug.idx(i, pc)]
			if factor.IsZero() {
				continue
			}
			for j := range cols {
				ii, pi := aug.idx(i, j), aug.idx(pivotRow, j)
				d[ii] = d[ii].Sub(factor.Mul(d[pi]))
			}
		}

		pivotCols = append(pivotCols, pc)
		pivotRow++
	}

	// Consistency: any non-pivot row with a non-zero entry in the b column.
	for i := pivotRow; i < rows; i++ {
		if !d[aug.idx(i, numVars)].IsZero() {
			return nil, ErrFailed.WithMessage("system is inconsistent: no solution exists")
		}
	}

	// Extract solution.
	sol := make([]S, numVars)
	for i := range numVars {
		sol[i] = field.Zero()
	}
	for i, pc := range pivotCols {
		sol[pc] = d[aug.idx(i, numVars)]
	}
	return sol, nil
}
