package u256_test

import (
	"bytes"
	crand "crypto/rand"
	"encoding/hex"
	"io"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/u256"
)

func Test_Add(t *testing.T) {
	samples := prepareSamples(t)

	for _, lBytes := range samples {
		for _, rBytes := range samples {
			leftU256 := u256.NewFromBytesLe(lBytes[:])
			rightU256 := u256.NewFromBytesLe(rBytes[:])
			sumU256 := leftU256.Add(rightU256).ToBytesLe()

			leftNat := new(saferith.Nat).SetBytes(bitstring.ReverseBytes(lBytes[:]))
			rightNat := new(saferith.Nat).SetBytes(bitstring.ReverseBytes(rBytes[:]))
			sumNat := bitstring.ReverseBytes(new(saferith.Nat).Add(leftNat, rightNat, 256).Bytes())

			if !bytes.Equal(sumU256, sumNat) {
				println()
				println(hex.EncodeToString(sumU256))
				println(hex.EncodeToString(sumNat))
			}
			require.True(t, bytes.Equal(sumU256, sumNat))
		}
	}
}

func Test_Sub(t *testing.T) {
	samples := prepareSamples(t)

	for _, lBytes := range samples {
		for _, rBytes := range samples {
			leftU256 := u256.NewFromBytesLe(lBytes[:])
			rightU256 := u256.NewFromBytesLe(rBytes[:])
			sumU256 := leftU256.Sub(rightU256).ToBytesLe()

			leftNat := new(saferith.Nat).SetBytes(bitstring.ReverseBytes(lBytes[:]))
			rightNat := new(saferith.Nat).SetBytes(bitstring.ReverseBytes(rBytes[:]))
			sumNat := bitstring.ReverseBytes(new(saferith.Nat).Sub(leftNat, rightNat, 256).Bytes())

			require.True(t, bytes.Equal(sumU256, sumNat))
		}
	}
}

func Test_Mul(t *testing.T) {
	samples := prepareSamples(t)

	for _, lBytes := range samples {
		for _, rBytes := range samples {
			leftU256 := u256.NewFromBytesLe(lBytes[:])
			rightU256 := u256.NewFromBytesLe(rBytes[:])
			sumU256 := leftU256.Mul(rightU256).ToBytesLe()

			leftNat := new(saferith.Nat).SetBytes(bitstring.ReverseBytes(lBytes[:]))
			rightNat := new(saferith.Nat).SetBytes(bitstring.ReverseBytes(rBytes[:]))
			sumNat := bitstring.ReverseBytes(new(saferith.Nat).Mul(leftNat, rightNat, 256).Bytes())

			require.True(t, bytes.Equal(sumU256, sumNat))
		}
	}
}

func prepareSamples(t require.TestingT) [][32]byte {
	samples := make([][32]byte, 0)
	for i := 0; i < 128; i++ {
		var sample [32]byte
		_, err := io.ReadFull(crand.Reader, sample[:])
		require.NoError(t, err)
		samples = append(samples, sample)
	}

	// add some edge cases
	samples = append(samples, [32]byte{
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
	})
	samples = append(samples, [32]byte{
		1, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
	})
	samples = append(samples, [32]byte{
		0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
		0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
		0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
		0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
	})
	samples = append(samples, [32]byte{
		0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
		0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
		0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
		0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x80,
	})
	samples = append(samples, [32]byte{
		0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
		0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
		0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
		0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
	})
	samples = append(samples, [32]byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	})

	return samples
}
