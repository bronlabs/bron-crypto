# mat

Generic matrix package over finite rings.

## Types

| Type | Description |
|------|-------------|
| `MatrixModule[S]` | Module structure for rectangular matrices. Factory for `Matrix[S]`. |
| `Matrix[S]` | Generic m×n rectangular matrix over a finite ring element `S`. |
| `MatrixAlgebra[S]` | Algebra structure for square matrices. Factory for `SquareMatrix[S]`. |
| `SquareMatrix[S]` | Generic n×n square matrix with determinant, inverse, trace. |

Both matrix types are generic over a scalar `S` constrained by `algebra.RingElement[S]`.
The ring must implement `algebra.FiniteRing[S]` to support random sampling and hashing.

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
// Mx = b (column span): returns x as n×1 matrix.
x, err := m.Spans(b)
// xM = r (row span): returns x as m×1 matrix.
x, err = m.RowSpans(r)
```

### Immutable vs Assign

Most operations come in pairs:

| Immutable | In-place |
|-----------|----------|
| `Add` | `AddAssign` |
| `Sub` | `SubAssign` |
| `Neg` | `NegAssign` |
| `ScalarMul` | `ScalarMulAssign` |
| `SwapRow` | `SwapRowAssign` |
| ... | ... |

Immutable methods clone the receiver, apply the operation, and return the new matrix.
Assign methods mutate the receiver directly.

### Storage

Elements are stored in a flat `[]S` slice in row-major order. Index `(i, j)` maps to
`data[i*cols + j]`.
