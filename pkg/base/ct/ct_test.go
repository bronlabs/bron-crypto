package ct_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
)

// TestChoice tests the Choice/Bool type and its Not() method
func TestChoice(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		choice   ct.Choice
		expected ct.Choice
	}{
		{"Not(0)", ct.Zero, ct.One},
		{"Not(1)", ct.One, ct.Zero},
		{"Not(False)", ct.False, ct.True},
		{"Not(True)", ct.True, ct.False},
		{"Not(2) normalizes", ct.Choice(2), ct.One},
		{"Not(3) normalizes", ct.Choice(3), ct.Zero},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.choice.Not())
		})
	}
}
