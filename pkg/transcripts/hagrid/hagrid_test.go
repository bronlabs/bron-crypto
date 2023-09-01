package hagrid_test

import (
	"fmt"
	"testing"

	"github.com/copperexchange/knox-primitives/pkg/transcripts/hagrid"
	"github.com/copperexchange/knox-primitives/pkg/transcripts/merlin"
)

func TestSimpleTranscript(t *testing.T) {
	mt := hagrid.NewTranscript("test protocol")
	mt.AppendMessages("some label", []byte("some data"))

	cBytes := mt.ExtractBytes("challenge", 32)
	cHex := fmt.Sprintf("%x", cBytes)
	expectedHex := "25f0fee7cff96c33627d39bd13729a150967f3e154c8c8863b6449f3798de882"

	if cHex != expectedHex {
		t.Errorf("\nGot : %s\nWant: %s", cHex, expectedHex)
	}
}

func TestComplexTranscript(t *testing.T) {
	tr := hagrid.NewTranscript("test protocol")
	tr.AppendMessages("step1", []byte("some data"))

	data := make([]byte, 1024)
	for i := range data {
		data[i] = 99
	}

	var chlBytes []byte
	for i := 0; i < 32; i++ {
		chlBytes = tr.ExtractBytes("challenge", 32)
		tr.AppendMessages("bigdata", data)
		tr.AppendMessages("challengedata", chlBytes)
	}

	expectedChlHex := "4d7b81464cf26b51a76dcef82c459736ed92bf1105fd6323d0c89bb2bc36abcd"
	chlHex := fmt.Sprintf("%x", chlBytes)

	if chlHex != expectedChlHex {
		t.Errorf("\nGot : %s\nWant: %s", chlHex, expectedChlHex)
	}
}

func BenchmarkTranscript_AppendMessages(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping test in short mode.")
	}
	label := "test transcript"
	h := hagrid.NewTranscript(label)
	m := merlin.NewTranscript(label)
	b.Run("Hagrid", func(b *testing.B) {
		for n := 0; n <= b.N; n += 1 {
			for i := 0; i <= 10000; i += 1 {
				h.AppendMessages("step1", []byte(fmt.Sprintf("some data %d", i)))
			}
		}
	})
	b.Run("Merlin", func(b *testing.B) {
		for n := 0; n <= b.N; n += 1 {
			for i := 0; i <= 10000; i += 1 {
				m.AppendMessages("step1", []byte(fmt.Sprintf("some data %d", i)))
			}
		}
	})
}
