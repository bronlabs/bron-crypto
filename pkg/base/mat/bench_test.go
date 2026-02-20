package mat

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
)

type benchS = *k256.Scalar

func benchRing() *k256.ScalarField {
	return k256.NewScalarField()
}

func benchScalar(v uint64) benchS {
	return k256.NewScalarField().FromUint64(v)
}

// --- Original Matrix setup ---

func benchOriginalMatrix(n int) *Matrix[benchS] {
	ring := benchRing()
	data := make([]benchS, n*n)
	for i := range data {
		data[i] = ring.FromUint64(uint64(i + 1))
	}
	return &Matrix[benchS]{rows: n, cols: n, data: data}
}

// --- Trait Matrix setup ---

func benchTraitMatrix(n int) *Matrix2[benchS] {
	ring := benchRing()
	m := &Matrix2[benchS]{}
	m.init(n, n)
	for i := range m.v {
		m.v[i] = ring.FromUint64(uint64(i + 1))
	}
	return m
}

// --- Add benchmarks ---

func BenchmarkOriginal_Add_4x4(b *testing.B) {
	a := benchOriginalMatrix(4)
	other := benchOriginalMatrix(4)
	b.ResetTimer()
	for b.Loop() {
		_ = a.Add(other)
	}
}

func BenchmarkTrait_Add_4x4(b *testing.B) {
	a := benchTraitMatrix(4)
	other := benchTraitMatrix(4)
	b.ResetTimer()
	for b.Loop() {
		_ = a.Add(other)
	}
}

func BenchmarkOriginal_Add_16x16(b *testing.B) {
	a := benchOriginalMatrix(16)
	other := benchOriginalMatrix(16)
	b.ResetTimer()
	for b.Loop() {
		_ = a.Add(other)
	}
}

func BenchmarkTrait_Add_16x16(b *testing.B) {
	a := benchTraitMatrix(16)
	other := benchTraitMatrix(16)
	b.ResetTimer()
	for b.Loop() {
		_ = a.Add(other)
	}
}

// --- AddMut benchmarks ---

func BenchmarkOriginal_AddMut_4x4(b *testing.B) {
	a := benchOriginalMatrix(4)
	other := benchOriginalMatrix(4)
	b.ResetTimer()
	for b.Loop() {
		a.AddMut(other)
	}
}

func BenchmarkTrait_AddMut_4x4(b *testing.B) {
	a := benchTraitMatrix(4)
	other := benchTraitMatrix(4)
	b.ResetTimer()
	for b.Loop() {
		a.AddMut(other)
	}
}

func BenchmarkOriginal_AddMut_16x16(b *testing.B) {
	a := benchOriginalMatrix(16)
	other := benchOriginalMatrix(16)
	b.ResetTimer()
	for b.Loop() {
		a.AddMut(other)
	}
}

func BenchmarkTrait_AddMut_16x16(b *testing.B) {
	a := benchTraitMatrix(16)
	other := benchTraitMatrix(16)
	b.ResetTimer()
	for b.Loop() {
		a.AddMut(other)
	}
}

// --- ScalarMul benchmarks ---

func BenchmarkOriginal_ScalarMul_4x4(b *testing.B) {
	a := benchOriginalMatrix(4)
	s := benchScalar(7)
	b.ResetTimer()
	for b.Loop() {
		_ = a.ScalarMul(s)
	}
}

// --- Neg benchmarks ---

func BenchmarkOriginal_Neg_4x4(b *testing.B) {
	a := benchOriginalMatrix(4)
	b.ResetTimer()
	for b.Loop() {
		_ = a.Neg()
	}
}

func BenchmarkTrait_Neg_4x4(b *testing.B) {
	a := benchTraitMatrix(4)
	b.ResetTimer()
	for b.Loop() {
		_ = a.Neg()
	}
}

// --- Clone benchmarks ---

func BenchmarkOriginal_Clone_4x4(b *testing.B) {
	a := benchOriginalMatrix(4)
	b.ResetTimer()
	for b.Loop() {
		_ = a.Clone()
	}
}

func BenchmarkTrait_Clone_4x4(b *testing.B) {
	a := benchTraitMatrix(4)
	b.ResetTimer()
	for b.Loop() {
		_ = a.Clone()
	}
}

func BenchmarkOriginal_Clone_16x16(b *testing.B) {
	a := benchOriginalMatrix(16)
	b.ResetTimer()
	for b.Loop() {
		_ = a.Clone()
	}
}

func BenchmarkTrait_Clone_16x16(b *testing.B) {
	a := benchTraitMatrix(16)
	b.ResetTimer()
	for b.Loop() {
		_ = a.Clone()
	}
}

// --- IsZero benchmarks ---

func BenchmarkOriginal_IsZero_4x4(b *testing.B) {
	a := benchOriginalMatrix(4)
	b.ResetTimer()
	for b.Loop() {
		_ = a.IsZero()
	}
}

func BenchmarkTrait_IsZero_4x4(b *testing.B) {
	a := benchTraitMatrix(4)
	b.ResetTimer()
	for b.Loop() {
		_ = a.IsZero()
	}
}
