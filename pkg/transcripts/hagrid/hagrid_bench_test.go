package hagrid_test

import (
	"fmt"
	"testing"

	"github.com/copperexchange/krypton/pkg/transcripts/hagrid"
)

func BenchmarkTranscript_AppendMessages(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping test in short mode.")
	}
	label := "test transcript"
	h := hagrid.NewTranscript(label)
	b.Run("Hagrid", func(b *testing.B) {
		for n := 0; n <= b.N; n += 1 {
			for i := 0; i <= 10000; i += 1 {
				h.AppendMessages("step1", []byte(fmt.Sprintf("some data %d", i)))
			}
		}
	})
}
