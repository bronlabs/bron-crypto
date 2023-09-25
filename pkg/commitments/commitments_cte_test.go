package commitments_test

import (
	"os"
	"testing"

	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/internal"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
)

func Test_MeasureConstantTime_commit(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	h := sha3.New256
	var message []byte
	internal.RunMeasurement(500, "commitments_commit", func(i int) {
		message = internal.GetBigEndianBytesWithLowestBitsSet(64, i)
	}, func() {
		commitments.Commit(h, message)
	})
}

func Test_MeasureConstantTime_open(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	h := sha3.New256
	var witness commitments.Witness
	var commitment commitments.Commitment
	var message []byte
	internal.RunMeasurement(500, "commitments_commit", func(i int) {
		message := internal.GetBigEndianBytesWithLowestBitsSet(64, i)
		commitment, witness, _ = commitments.Commit(h, message)
	}, func() {
		for i := 0; i < 200; i++ {
			commitments.Open(h, message, commitment, witness)
		}
	})
}
