package testutils

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

/*.-------------------------------- Bytes -----------------------------------.*/

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

/*.------------------------------ Transcrips --------------------------------.*/

func MakeTranscripts(label string, identities []types.IdentityKey) (allTranscripts []transcripts.Transcript) {
	allTranscripts = make([]transcripts.Transcript, len(identities))
	for i := range identities {
		allTranscripts[i] = hagrid.NewTranscript(label, nil)
	}
	return allTranscripts
}

func TranscriptAtSameState(label string, allTranscripts []transcripts.Transcript) (bool, error) {
	for i := 0; i < len(allTranscripts); i++ {
		l, err := allTranscripts[i].ExtractBytes(label, base.CollisionResistanceBytes)
		if err != nil {
			return false, errs.WrapFailed(err, "could not extract transcript")
		}
		for j := i + 1; j < len(allTranscripts); j++ {
			r, err := allTranscripts[j].ExtractBytes(label, base.CollisionResistanceBytes)
			if err != nil {
				return false, errs.WrapFailed(err, "could not extract transcript")
			}
			if !bytes.Equal(l, r) {
				return false, nil
			}
		}
	}

	return true, nil
}
