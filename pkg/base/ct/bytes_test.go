package ct_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
)

// TestCompareBytes tests the BytesCompare function
func TestCompareBytes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		x, y       []byte
		lt, eq, gt ct.Bool
	}{
		{"equal", []byte{1, 2, 3}, []byte{1, 2, 3}, ct.False, ct.True, ct.False},
		{"x < y first byte", []byte{1, 2, 3}, []byte{2, 2, 3}, ct.True, ct.False, ct.False},
		{"x > y first byte", []byte{2, 2, 3}, []byte{1, 2, 3}, ct.False, ct.False, ct.True},
		{"x < y middle byte", []byte{1, 2, 3}, []byte{1, 3, 3}, ct.True, ct.False, ct.False},
		{"x > y middle byte", []byte{1, 3, 3}, []byte{1, 2, 3}, ct.False, ct.False, ct.True},
		{"x < y last byte", []byte{1, 2, 3}, []byte{1, 2, 4}, ct.True, ct.False, ct.False},
		{"x > y last byte", []byte{1, 2, 4}, []byte{1, 2, 3}, ct.False, ct.False, ct.True},
		{"x prefix of y", []byte{1, 2}, []byte{1, 2, 3}, ct.True, ct.False, ct.False},
		{"y prefix of x", []byte{1, 2, 3}, []byte{1, 2}, ct.False, ct.False, ct.True},
		{"empty vs non-empty", []byte{}, []byte{1}, ct.True, ct.False, ct.False},
		{"non-empty vs empty", []byte{1}, []byte{}, ct.False, ct.False, ct.True},
		{"both empty", []byte{}, []byte{}, ct.False, ct.True, ct.False},
		{"lexicographic", []byte{1, 255}, []byte{2, 0}, ct.True, ct.False, ct.False},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			lt, eq, gt := ct.CompareBytes(tt.x, tt.y)
			assert.Equal(t, tt.lt, lt, "lt")
			assert.Equal(t, tt.eq, eq, "eq")
			assert.Equal(t, tt.gt, gt, "gt")
		})
	}
}

func TestAndBytes(t *testing.T) {
	t.Parallel()

	t.Run("equal lengths", func(t *testing.T) {
		t.Parallel()
		dst := make([]byte, 3)
		n := ct.AndBytes(dst, []byte{0xff, 0x0f, 0xf0}, []byte{0x0f, 0xff, 0x0f})
		require.Equal(t, 3, n)
		require.Equal(t, []byte{0x0f, 0x0f, 0x00}, dst)
	})

	t.Run("panic on different lengths", func(t *testing.T) {
		t.Parallel()
		assert.Panics(t, func() {
			ct.AndBytes(make([]byte, 3), []byte{1, 2, 3}, []byte{1})
		})
	})
}

func TestOrBytes(t *testing.T) {
	t.Parallel()

	t.Run("equal lengths", func(t *testing.T) {
		t.Parallel()
		dst := make([]byte, 3)
		n := ct.OrBytes(dst, []byte{0xf0, 0x0f, 0x00}, []byte{0x0f, 0xf0, 0x0f})
		require.Equal(t, 3, n)
		require.Equal(t, []byte{0xff, 0xff, 0x0f}, dst)
	})

	t.Run("panic on different lengths", func(t *testing.T) {
		t.Parallel()
		assert.Panics(t, func() {
			ct.OrBytes(make([]byte, 3), []byte{1, 2, 3}, []byte{1})
		})
	})
}
