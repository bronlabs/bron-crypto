// Package mat provides generic matrix types over finite algebraic structures.
//
// The package implements three matrix types:
//
//   - [Matrix] for general rectangular matrices over a finite ring.
//   - [SquareMatrix] for square matrices with additional algebraic operations
//     (determinant, inverse, trace, multiplication).
//   - [ModuleValuedMatrix] for rectangular matrices whose entries are elements
//     of a finite module (e.g. elliptic curve points) rather than ring elements.
//
// Ring-valued matrices ([Matrix] and [SquareMatrix]) are generic over a scalar
// type S constrained by [algebra.RingElement], and require the ring to implement
// [algebra.FiniteRing] (providing Random and Hash capabilities).
//
// Module-valued matrices ([ModuleValuedMatrix]) are generic over an element type
// E constrained by [algebra.ModuleElement] and a scalar type S constrained by
// [algebra.RingElement]. They support the group operation (element-wise addition)
// and scalar multiplication, but not ring operations like matrix–matrix multiplication.
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
//   - [ModuleValuedMatrixModule] is the structure for module-valued matrices.
//     Create one with [NewModuleValuedMatrixModule], or use [Lift] to
//     convert a scalar matrix into a module-valued matrix via a base point.
//
// Elements are stored in row-major order in a flat slice. Most operations come
// in two variants: an immutable version that returns a new matrix (e.g. Add)
// and an in-place version suffixed with Assign (e.g. AddAssign).
//
// The implementation uses a trait-based generic design via [MatrixGroupTrait],
// [MatrixModuleTrait], [MatrixGroupElementTrait], and [MatrixTrait] to share
// code between all matrix types.
// Square matrices use a RectW type parameter so that operations like Augment
// and Stack can return rectangular matrices even when called on square matrices.
package mat
