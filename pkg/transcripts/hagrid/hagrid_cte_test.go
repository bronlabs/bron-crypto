package hagrid_test

import (
	"os"
	"testing"

	"github.com/copperexchange/krypton-primitives/internal"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

func Test_MeasureConstantTime_append(t *testing.T) {
	t.Parallel()
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	mt := hagrid.NewTranscript("test protocol", nil)
	var msg []byte
	internal.RunMeasurement(32*8, "hagrid_append", func(i int) {
		msg = internal.GetBigEndianBytesWithLowestBitsSet(32, i)
	}, func() {
		mt.AppendMessages("some label", msg)
	})
}

func Test_MeasureConstantTime_extract(t *testing.T) {
	t.Parallel()
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	mt := hagrid.NewTranscript("test protocol", nil)
	var msg []byte
	internal.RunMeasurement(32*8, "hagrid_extract", func(i int) {
		msg = internal.GetBigEndianBytesWithLowestBitsSet(32, i)
		mt.AppendMessages("some label", msg)
	}, func() {
		mt.ExtractBytes("label", 32)
	})
}
