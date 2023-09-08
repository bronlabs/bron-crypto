package hashing_test

import (
	"os"
	"testing"

	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton/internal"
	"github.com/copperexchange/krypton/pkg/hashing"
)

func Test_MeasureConstantTime_FiatShamirDeterministic(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	var inputBytes []byte
	internal.RunMeasurement(500, "FiatShamirDeterministic", func(i int) {
		inputBytes = internal.GetBigEndianBytesWithLowestBitsSet(128, i)
	}, func() {
		hashing.FiatShamirHKDF(sha3.New256, inputBytes)
	})
}

func Test_MeasureConstantTime_sha3New256(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	var inputBytes []byte
	h := sha3.New256()
	internal.RunMeasurement(500, "sha3New256", func(i int) {
		inputBytes = internal.GetBigEndianBytesWithLowestBitsSet(128, i)
		h.Reset()
	}, func() {
		h.Write(inputBytes)
		h.Sum(nil)
	})
}
