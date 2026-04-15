# mat

Generic matrix package over finite algebraic structures.

## Types

| Type | Description |
|------|-------------|
| `MatrixModule[S]` | Module structure for rectangular matrices. Factory for `Matrix[S]`. |
| `Matrix[S]` | Generic m×n rectangular matrix over a finite ring element `S`. |
| `MatrixAlgebra[S]` | Algebra structure for square matrices. Factory for `SquareMatrix[S]`. |
| `SquareMatrix[S]` | Generic n×n square matrix with determinant, inverse, trace. |
| `ModuleValuedMatrixModule[E, S]` | Module structure for module-valued matrices. Factory for `ModuleValuedMatrix[E, S]`. |
| `ModuleValuedMatrix[E, S]` | Generic m×n matrix whose entries are module elements (e.g. curve points). |

Ring-valued matrices (`Matrix`, `SquareMatrix`) are generic over a scalar `S` constrained
by `algebra.RingElement[S]`. The ring must implement `algebra.FiniteRing[S]` to support
random sampling and hashing.

Module-valued matrices (`ModuleValuedMatrix`) are generic over an element type `E`
constrained by `algebra.ModuleElement[E, S]` and a scalar type `S`. They support group
operations (element-wise addition/negation) and scalar multiplication, but not ring
operations like matrix–matrix multiplication.

## Usage

```go
// Create a module for 2x3 matrices over a finite ring.
mod, _ := mat.NewMatrixModule(2, 3, finiteRing)

// Construct a matrix from rows.
m, _ := mod.New([][]S{{a, b, c}, {d, e, f}})

// Or from flat row-major data.
m, _ = mod.NewRowMajor(a, b, c, d, e, f)

// Random and deterministic hash construction.
r, _ := mod.Random(rand.Reader)
h, _ := mod.Hash([]byte("domain separator"))

// Create a 3x3 square matrix algebra.
alg, _ := mat.NewMatrixAlgebra(3, finiteRing)
id := alg.Identity()
sq, _ := alg.New([][]S{{...}, {...}, {...}})

// Arithmetic (immutable — returns new matrices).
sum := m.Add(other)
diff := m.Sub(other)
neg := m.Neg()
scaled := m.ScalarMul(s)

// In-place variants (mutate the receiver).
m.AddAssign(other)
m.NegAssign()
m.ScalarMulAssign(s)

// Square matrix operations.
det := sq.Determinant()
inv, err := sq.TryInv()
tr := sq.Trace()
product := sq.Mul(other)

// Solve linear systems.
// Mx = b (right solve): returns x as n×1 matrix.
x, err := mat.SolveRight(m, b)
// xM = r (left solve): returns x as m×1 matrix.
x, err = mat.SolveLeft(m, r)
```

### Module-valued matrices

```go
// Create a module for 2x2 matrices over curve points.
mvMod, _ := mat.NewModuleValuedMatrixModule(2, 2, curve)

// Construct from module elements.
mv, _ := mvMod.New([][]E{{p1, p2}, {p3, p4}})

// Lift a scalar matrix into module-valued via a base point.
lifted, _ := mat.Lift(scalarMatrix, basePoint)

// Group operations (element-wise point addition).
sum := mv.Op(other)
inv := mv.OpInv()

// Scalar multiplication (multiply each element by a scalar).
scaled := mv.ScalarOp(s)
```

### Immutable vs Assign

Most operations come in pairs:

| Immutable | In-place |
|-----------|----------|
| `Add` | `AddAssign` |
| `Sub` | `SubAssign` |
| `Neg` | `NegAssign` |
| `ScalarMul` | `ScalarMulAssign` |
| `Op` | `OpAssign` |
| `OpInv` | `OpInvAssign` |
| `ScalarOp` | `ScalarOpAssign` |
| `SwapRow` | `SwapRowAssign` |
| ... | ... |

Immutable methods clone the receiver, apply the operation, and return the new matrix.
Assign methods mutate the receiver directly.

### Storage

Elements are stored in a flat slice in row-major order. Index `(i, j)` maps to
`data[i*cols + j]`.
