package hagrid_test

import (
	"fmt"
	"testing"

	"github.com/copperexchange/knox-primitives/pkg/transcripts/hagrid"
)

func TestSimpleTranscript(t *testing.T) {
	mt := hagrid.NewTranscript("test protocol")
	mt.AppendMessages("some label", []byte("some data"))

	cBytes, _ := mt.ExtractBytes("challenge", 32)
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
		chlBytes, _ = tr.ExtractBytes("challenge", 32)
		tr.AppendMessages("bigdata", data)
		tr.AppendMessages("challengedata", chlBytes)
	}

	expectedChlHex := "4d7b81464cf26b51a76dcef82c459736ed92bf1105fd6323d0c89bb2bc36abcd"
	chlHex := fmt.Sprintf("%x", chlBytes)

	if chlHex != expectedChlHex {
		t.Errorf("\nGot : %s\nWant: %s", chlHex, expectedChlHex)
	}
}
