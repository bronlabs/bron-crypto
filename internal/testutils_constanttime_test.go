package internal

import (
	"math/big"
	"os"
	"testing"

	"github.com/cronokirby/saferith"
)

func Test_MeasureConstantTime_bigint(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	mod := new(big.Int).SetBytes(GetBigEndianBytesWithLowestBitsSet(256, 256))
	b := new(big.Int)
	exp := new(big.Int)
	RunMeasurement(500, "bigint", func(i int) {
		exp = new(big.Int).SetBytes(GetBigEndianBytesWithLowestBitsSet(64, i))
		b.SetBytes(GetBigEndianBytesWithLowestBitsSet(512, 512))
	}, func() {
		b.Exp(b, exp, mod)
	})
}

func Test_MeasureConstantTime_saferith(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	mod := saferith.ModulusFromBytes(GetBigEndianBytesWithLowestBitsSet(256, 256))
	b := saferith.Nat{}
	exp := saferith.Nat{}
	RunMeasurement(500, "saferith", func(i int) {
		b.SetBytes(GetBigEndianBytesWithLowestBitsSet(512, 512))
		exp.SetBytes(GetBigEndianBytesWithLowestBitsSet(64, i))
	}, func() {
		b.Exp(&b, &exp, mod)
	})
}
