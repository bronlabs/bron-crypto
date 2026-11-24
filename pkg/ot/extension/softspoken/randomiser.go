package softspoken

import (
	"crypto/sha3"
	"encoding/binary"
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/ot"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

const (
	// randomiserLabel is the cSHAKE256 function name of the randomiser.
	randomiserLabel = "BRON_CRYPTO-SOFTSPOKEN-RANDOMISER"
	// saltLabel labels the extraction of the randomiser's salt from the
	// transcript.
	saltLabel = "BRON_CRYPTO-SOFTSPOKEN-SALT"
	// saltSize is the size of the salt in bytes.
	saltSize = 32
)

// randomiser is the hash H of the randomisation step of KOS15 Figure 10, the
// random oracle of the one-message SoftSpokenOT of DKLs23 Section 5.1:
// H(j, x) = cSHAKE256(j ‖ x) with randomiserLabel as the function name and the
// salt as the customisation string, truncated to one Message. The salt is
// extracted from the transcript once per extension, after the receiver's
// columns and check responses are bound to it, so every output is bound to the
// session and to the whole exchange so far and no (salt, j) pair repeats across
// sessions or extensions. The two hashes of one OT, on q_j and q_j ⊕ Δ,
// deliberately share j: that is the correlation the notion protects. Keccak
// has no data-dependent branches or table lookups, so the inputs, which are the
// OT secrets, stay out of timing side channels.
type randomiser struct {
	salt []byte
}

// newRandomiser fixes the salt of one extension.
func newRandomiser(salt []byte) (*randomiser, error) {
	if len(salt) != saltSize {
		return nil, ot.ErrInvalidArgument.WithMessage("salt must be %d bytes, got %d", saltSize, len(salt))
	}
	return &randomiser{salt: salt}, nil
}

// extractRandomiser extracts the salt of one extension from the transcript,
// which must already hold the columns and the check responses.
func extractRandomiser(transcript transcripts.Transcript) (*randomiser, error) {
	salt, err := transcript.ExtractBytes(saltLabel, saltSize)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot extract the randomiser salt")
	}
	return newRandomiser(salt)
}

// hash returns H(j, x) for OT index j.
func (h *randomiser) hash(index uint64, x Message) (Message, error) {
	var out Message
	var in [8 + len(out)]byte
	binary.LittleEndian.PutUint64(in[:8], index)
	copy(in[8:], x[:])

	xof := sha3.NewCSHAKE256([]byte(randomiserLabel), h.salt)
	if _, err := xof.Write(in[:]); err != nil {
		return out, errs.Wrap(err).WithMessage("cannot absorb the row")
	}
	if _, err := io.ReadFull(xof, out[:]); err != nil {
		return out, errs.Wrap(err).WithMessage("cannot squeeze the hash")
	}
	return out, nil
}
