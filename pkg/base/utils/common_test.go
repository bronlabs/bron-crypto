package utils_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/utils"
)

func TestBoolTo(t *testing.T) {
	t.Parallel()
	// Test true converts to 1
	require.Equal(t, 1, utils.BoolTo[int](true))

	// Test false converts to 0
	require.Equal(t, 0, utils.BoolTo[int](false))

	// Test with different integer types
	require.Equal(t, int64(1), utils.BoolTo[int64](true))
	require.Equal(t, uint8(0), utils.BoolTo[uint8](false))
}

func TestIsNil(t *testing.T) {
	t.Parallel()
	// Test nil pointer
	var nilPtr *int
	require.True(t, utils.IsNil(nilPtr))

	// Test non-nil pointer
	x := 42
	require.False(t, utils.IsNil(&x))
	// Test nil error interface
	var nilErr error
	require.True(t, utils.IsNil(nilErr))

	// Test regular value (not pointer or interface)
	require.False(t, utils.IsNil(42))
}

func TestLeadingZeroBytes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input []byte
		want  int
	}{
		{"empty slice", []byte{}, 0},
		{"no leading zeros", []byte{1, 2, 3}, 0},
		{"one leading zero", []byte{0, 1, 2, 3}, 1},
		{"two leading zeros", []byte{0, 0, 1, 2, 3}, 2},
		{"all zeros", []byte{0, 0, 0}, 3},
		{"trailing zeros only", []byte{1, 2, 0, 0}, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, utils.LeadingZeroBytes(tt.input))
		})
	}
}

// Test types for TestImplementsX
type Stringer interface {
	String() string
}

type MyString string

func (ms MyString) String() string {
	return string(ms)
}

type MyStringPtr string

func (msp *MyStringPtr) String() string {
	return string(*msp)
}

type MyInt int

func TestImplementsX(t *testing.T) {
	t.Parallel()
	// Test value receiver implementation
	ms := MyString("hello")
	_, ok := utils.ImplementsX[Stringer](ms)
	require.True(t, ok)

	// Test pointer receiver implementation
	msp := MyStringPtr("world")
	_, ok = utils.ImplementsX[Stringer](msp)
	require.True(t, ok)

	// Test non-implementing type
	mi := MyInt(42)
	_, ok = utils.ImplementsX[Stringer](mi)
	require.False(t, ok)
}

func TestBinomial(t *testing.T) {
	t.Parallel()
	tests := []struct {
		n, k int
		want int
	}{
		{5, 0, 1},    // C(5,0) = 1
		{5, 1, 5},    // C(5,1) = 5
		{5, 2, 10},   // C(5,2) = 10
		{5, 3, 10},   // C(5,3) = 10 (symmetry)
		{5, 5, 1},    // C(5,5) = 1
		{10, 3, 120}, // C(10,3) = 120
		{6, 2, 15},   // C(6,2) = 15
		{4, 2, 6},    // C(4,2) = 6
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			require.Equal(t, tt.want, utils.Binomial(tt.n, tt.k))
		})
	}
}
