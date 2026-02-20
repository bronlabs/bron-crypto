// Package mat provides generic matrix types over finite rings.
//
// The package implements two matrix types: [Matrix] for general rectangular
// matrices and [SquareMatrix] for square matrices with additional algebraic
// operations (determinant, inverse, trace). Both types are generic over a
// scalar type S constrained by [algebra.RingElement], and require the ring
// to implement [algebra.FiniteRing] (providing Random and Hash capabilities).
//
// Matrices are constructed through their associated module/algebra structures:
//
//   - [MatrixModule] is the structure for rectangular matrices. Create one with
//     [NewMatrixModule], then use its New, NewRowMajor, Random, or Hash
//     methods to construct matrices.
//
//   - [MatrixAlgebra] is the structure for square matrices. Create one with
//     [NewMatrixAlgebra], then use its New, NewRowMajor, Random, Hash,
//     or [MatrixAlgebra.Identity] methods to construct matrices.
//
// Elements are stored in row-major order in a flat slice. Most operations come
// in two variants: an immutable version that returns a new matrix (e.g. Add)
// and an in-place version suffixed with Assign (e.g. AddAssign).
//
// The implementation uses a trait-based generic design via [MatrixModuleTrait]
// and [MatrixTrait] to share code between rectangular and square matrix types.
// Square matrices use a RectW type parameter so that operations like Augment
// and Stack can return rectangular matrices even when called on square matrices.
package mat
