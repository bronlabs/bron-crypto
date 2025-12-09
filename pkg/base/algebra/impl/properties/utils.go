package properties

import (
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
)

func NewLowLevelUniformPrimeFieldElementGenerator[FPtr impl.PrimeFieldElementPtrLowLevel[FPtr, F], F any](t *testing.T, elementSize int) *rapid.Generator[FPtr] {
	t.Helper()

	require.Positive(t, elementSize, "element size must be positive")
	dataSize := elementSize + base.ComputationalSecurityBytesCeil
	uniformBytesGenerator := rapid.SliceOfN(rapid.Byte(), dataSize, dataSize)
	return rapid.Custom(func(t *rapid.T) FPtr {
		var fe F
		data := uniformBytesGenerator.Draw(t, "data")
		ok := FPtr(&fe).SetBytesWide(data)
		require.Equal(t, ct.True, ok)
		return &fe
	})
}
