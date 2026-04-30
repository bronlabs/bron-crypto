package properties

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

type SerialisationProperties[T any] struct {
	Generator *rapid.Generator[T]
	AreEqual  func(T, T) bool
}

func (p *SerialisationProperties[T]) CheckAll(t *testing.T) {
	t.Parallel()
	t.Run("Roundtrip", p.Roundtrip)
	t.Run("EncodingIsDeterministic", p.EncodingIsDeterministic)
	t.Run("InjectivityAcrossDifferentValues", p.InjectivityAcrossDifferentValues)
	t.Run("MalformedInputRejection", p.MalformedInputRejection)
}

func (p *SerialisationProperties[T]) Roundtrip(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		value := p.Generator.Draw(rt, "value")
		ser, err := serde.MarshalCBOR(value)
		require.NoError(t, err, "failed to marshal value")

		deserialised, err := serde.UnmarshalCBOR[T](ser)
		require.NoError(t, err, "failed to unmarshal value")

		require.True(t, p.AreEqual(value, deserialised), "original and deserialized values are not equal")
	})
}

func (p *SerialisationProperties[T]) EncodingIsDeterministic(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		value := p.Generator.Draw(rt, "value")
		ser1, err := serde.MarshalCBOR(value)
		require.NoError(t, err, "failed to marshal value first time")

		ser2, err := serde.MarshalCBOR(value)
		require.NoError(t, err, "failed to marshal value second time")

		require.Equal(t, ser1, ser2, "serialised bytes differ between runs")
	})
}

func (p *SerialisationProperties[T]) InjectivityAcrossDifferentValues(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		value1 := p.Generator.Draw(rt, "value 1")
		value2 := p.Generator.Filter(func(v T) bool {
			return !p.AreEqual(value1, v)
		}).Draw(rt, "value 2")

		ser1, err := serde.MarshalCBOR(value1)
		require.NoError(t, err, "failed to marshal value 1")

		ser2, err := serde.MarshalCBOR(value2)
		require.NoError(t, err, "failed to marshal value 2")

		require.NotEqual(t, ser1, ser2, "different values should have different serialisations")
	})
}

func (p *SerialisationProperties[T]) MalformedInputRejection(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		value := p.Generator.Draw(rt, "value")
		valid, err := serde.MarshalCBOR(value)
		require.NoError(t, err, "failed to marshal value")
		if len(valid) == 0 {
			return
		}
		truncateAt := rapid.IntRange(0, len(valid)-1).Draw(rt, "truncate length")
		malformed := valid[:truncateAt]

		out, err := serde.UnmarshalCBOR[T](malformed)
		require.Error(t, err, "expected error when unmarshalling truncated input %x", malformed)
		require.True(t, p.AreEqual(*new(T), out), "output should be zero value on error")
	})
}
