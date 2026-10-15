package znstar_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
)

// TestElement_CBOR_MalformedArithmetic feeds the known-order element decoders
// payloads whose arithmetic is absent, null, empty, or built from degenerate
// factors. Each must fail cleanly: the arithmetic carries the factorisation,
// and the modular constructors assume well-formed factors.
func TestElement_CBOR_MalformedArithmetic(t *testing.T) {
	t.Parallel()

	empty := map[string]any{}
	cases := []struct {
		name    string
		payload any
	}{
		{"arithmetic omitted", empty},
		{"arithmetic null", map[string]any{"arithmetic": nil}},
		{"arithmetic empty", map[string]any{"arithmetic": empty}},
		{"arithmetic with zero factors", map[string]any{"arithmetic": map[string]any{"p": empty, "q": empty}}},
		{"arithmetic with factor one", map[string]any{"arithmetic": map[string]any{"p": numct.NewNat(1), "q": numct.NewNat(11)}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			data, err := serde.MarshalCBOR(tc.payload)
			require.NoError(t, err)

			require.NotPanics(t, func() { _, err = serde.UnmarshalCBOR[*znstar.PaillierGroupElementKnownOrder](data) })
			require.Error(t, err)
			require.NotPanics(t, func() { _, err = serde.UnmarshalCBOR[*znstar.RSAGroupElementKnownOrder](data) })
			require.Error(t, err)
		})
	}
}
