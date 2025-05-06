package testutils

import (
	"encoding/hex"
	"encoding/json"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/simple"
	"strings"
	"testing"
)

type HexBytes []byte

func (h *HexBytes) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return errs.WrapFailed(err, "could not unmarshal hex bytes")
	}
	if s == "" {
		*h = nil
		return nil
	}

	hexStr := strings.TrimPrefix(s, "0x")

	decoded, err := hex.DecodeString(hexStr)
	if err != nil {
		return errs.WrapFailed(err, "could not decode hex bytes")
	}
	*h = decoded
	return nil
}

type HexBytesArray [][]byte

func (h *HexBytesArray) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return errs.WrapFailed(err, "could not unmarshal hex bytes")
	}

	if s == "" {
		*h = nil
		return nil
	}

	hexes := strings.Split(s, ",")

	decoded := make([][]byte, len(hexes))

	for i, h := range hexes {
		var err error
		hexStr := strings.TrimPrefix(h, "0x")
		decoded[i], err = hex.DecodeString(hexStr)
		if err != nil {
			return errs.WrapFailed(err, "could not decode hex bytes")
		}
	}
	*h = decoded
	return nil
}

func MakeTranscripts(_ testing.TB, dst string, identities []types.IdentityKey) []transcripts.Transcript {
	tape := simple.NewTranscript(dst)
	tapes := make([]transcripts.Transcript, len(identities))
	for i := range identities {
		tapes[i] = tape.Clone()
	}
	return tapes
}
