package numct_test

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"

	_ "embed"
)

//go:embed testvectors/vectors.json
var testVectorsData string

// hexNat unmarshals a hex string (no 0x prefix) into *numct.Nat
type hexNat struct {
	*numct.Nat
}

func (h *hexNat) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	n := new(big.Int)
	n.SetString(s, 16)
	h.Nat = numct.NewNatFromBig(n, n.BitLen())
	return nil
}

// hexInt unmarshals a hex string (may have - prefix) into *numct.Int
type hexInt struct {
	*numct.Int
}

func (h *hexInt) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	n := new(big.Int)
	n.SetString(s, 16)
	h.Int = numct.NewIntFromBig(n, n.BitLen())
	return nil
}

type natSqrtVector struct {
	N    hexNat `json:"n"`
	Root hexNat `json:"root"`
	Ok   bool   `json:"ok"`
}

type natBinaryOpVector struct {
	A hexNat `json:"a"`
	B hexNat `json:"b"`
	C hexNat `json:"c"`
}

type intSqrtVector struct {
	N    hexInt `json:"n"`
	Root hexInt `json:"root"`
	Ok   bool   `json:"ok"`
}

type intBinaryOpVector struct {
	A hexInt `json:"a"`
	B hexInt `json:"b"`
	C hexInt `json:"c"`
}

type testVectors struct {
	NatSqrt []natSqrtVector     `json:"nat_sqrt"`
	NatAnd  []natBinaryOpVector `json:"nat_and"`
	NatOr   []natBinaryOpVector `json:"nat_or"`
	NatXor  []natBinaryOpVector `json:"nat_xor"`
	IntSqrt []intSqrtVector     `json:"int_sqrt"`
	IntAnd  []intBinaryOpVector `json:"int_and"`
	IntOr   []intBinaryOpVector `json:"int_or"`
	IntXor  []intBinaryOpVector `json:"int_xor"`
}

func testNatSqrt(t *testing.T, vectors []natSqrtVector) {
	t.Helper()
	for i, v := range vectors {
		var result numct.Nat
		ok := result.Sqrt(v.N.Nat)
		if v.Ok {
			require.Equal(t, ct.True, ok, "vector %d: expected ok=true", i)
			require.Equal(t, ct.True, result.Equal(v.Root.Nat), "vector %d: sqrt mismatch, got %s, want %s", i, result.Big().Text(16), v.Root.Big().Text(16))
		} else {
			require.Equal(t, ct.False, ok, "vector %d: expected ok=false", i)
		}
	}
}

func testNatBinaryOp(t *testing.T, vectors []natBinaryOpVector, op func(*numct.Nat, *numct.Nat, *numct.Nat), name string) {
	t.Helper()
	for i, v := range vectors {
		var result numct.Nat
		op(&result, v.A.Nat, v.B.Nat)
		require.Equal(t, ct.True, result.Equal(v.C.Nat), "vector %d: %s(%s, %s) = %s, want %s", i, name, v.A.Big().Text(16), v.B.Big().Text(16), result.Big().Text(16), v.C.Big().Text(16))
	}
}

func testIntSqrt(t *testing.T, vectors []intSqrtVector) {
	t.Helper()
	for i, v := range vectors {
		var result numct.Int
		ok := result.Sqrt(v.N.Int)
		if v.Ok {
			require.Equal(t, ct.True, ok, "vector %d: expected ok=true", i)
			require.Equal(t, ct.True, result.Equal(v.Root.Int), "vector %d: sqrt mismatch, got %s, want %s", i, result.Big().Text(16), v.Root.Big().Text(16))
		} else {
			require.Equal(t, ct.False, ok, "vector %d: expected ok=false", i)
		}
	}
}

func testIntBinaryOp(t *testing.T, vectors []intBinaryOpVector, op func(*numct.Int, *numct.Int, *numct.Int), name string) {
	t.Helper()
	for i, v := range vectors {
		var result numct.Int
		op(&result, v.A.Int, v.B.Int)
		require.Equal(t, ct.True, result.Equal(v.C.Int), "vector %d: %s(%s, %s) = %s, want %s", i, name, v.A.Big().Text(16), v.B.Big().Text(16), result.Big().Text(16), v.C.Big().Text(16))
	}
}

func TestVectors(t *testing.T) {
	t.Parallel()
	var vectors testVectors
	err := json.Unmarshal([]byte(testVectorsData), &vectors)
	require.NoError(t, err)

	t.Run("nat_sqrt", func(t *testing.T) {
		t.Parallel()
		testNatSqrt(t, vectors.NatSqrt)
	})
	t.Run("nat_and", func(t *testing.T) {
		t.Parallel()
		testNatBinaryOp(t, vectors.NatAnd, (*numct.Nat).And, "And")
	})
	t.Run("nat_or", func(t *testing.T) {
		t.Parallel()
		testNatBinaryOp(t, vectors.NatOr, (*numct.Nat).Or, "Or")
	})
	t.Run("nat_xor", func(t *testing.T) {
		t.Parallel()
		testNatBinaryOp(t, vectors.NatXor, (*numct.Nat).Xor, "Xor")
	})
	t.Run("int_sqrt", func(t *testing.T) {
		t.Parallel()
		testIntSqrt(t, vectors.IntSqrt)
	})
	t.Run("int_and", func(t *testing.T) {
		t.Parallel()
		testIntBinaryOp(t, vectors.IntAnd, (*numct.Int).And, "And")
	})
	t.Run("int_or", func(t *testing.T) {
		t.Parallel()
		testIntBinaryOp(t, vectors.IntOr, (*numct.Int).Or, "Or")
	})
	t.Run("int_xor", func(t *testing.T) {
		t.Parallel()
		testIntBinaryOp(t, vectors.IntXor, (*numct.Int).Xor, "Xor")
	})
}
