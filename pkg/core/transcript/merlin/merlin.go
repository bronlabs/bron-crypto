package merlin

import (
	"encoding/binary"
	"hash"
	"io"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/mimoo/StrobeGo/strobe"
)

const (
	merlinProtocolLabel  = "Merlin v1.1"
	domainSeparatorLabel = "<@>"
	securityParameter    = 256
)

type Transcript struct {
	s strobe.Strobe
}

// NewTranscript creates a new transcript with the supplied application label. The
// computational security parameter is set to 256 bits.
func NewTranscript(appLabel string) *Transcript {
	t := Transcript{
		s: strobe.InitStrobe(merlinProtocolLabel, securityParameter),
	}
	t.AppendMessage([]byte(domainSeparatorLabel), []byte(appLabel))
	return &t
}

// Clone returns a copy of the transcript.
func (t *Transcript) Clone() *Transcript {
	s := t.s.Clone()
	return &Transcript{s: *s}
}

// ----------------------------- WRITE OPS ---------------------------------- //
// Append adds the message to the transcript with the supplied label.
func (t *Transcript) AppendMessage(label, message []byte) {
	// AdditionalData[label || le32(len(message))]
	t.s.AD(true, t.appendSizeToLabel(label, len(message)))
	// AdditionalData[message]
	t.s.AD(false, message)
}

func (t *Transcript) AppendHashedMessage(label, message []byte, h hash.Hash) (err error) {
	// Hash message
	if _, err := h.Write(message); err != nil {
		return errs.WrapFailed(err, "failed to hash message for transcript")
	}
	// AdditionalData[label || le32(len(message))]
	t.s.AD(true, t.appendSizeToLabel(label, len(message)))
	// Append hash to transcript
	t.s.AD(false, h.Sum(nil))
	return nil
}

// ReseedWithWitness re-keys the transcript with witness data.
func (t *Transcript) ReseedWithWitness(label, witness []byte) *Transcript {
	// AdditionalData[label || le32(len(witness))]
	t.s.AD(true, t.appendSizeToLabel(label, len(witness)))
	// KEY inserts a key into the state. It also provides forward secrecy.
	t.s.KEY(witness)
	return t
}

// Finalize uses the supplied rng to re-key the transcript. It ensures that
// the transcript cannot be synchronized with any other transcript unless they
// share the same rng (with the same state).
func (t *Transcript) Finalize(rng io.Reader) (*Transcript, error) {
	// Generate a random key from the supplied rng.
	var keyBytes [32]byte // 256 bits
	if _, err := rng.Read(keyBytes[:]); err != nil {
		return nil, errs.WrapFailed(err, "failed to read random bytes for transcript")
	}
	// AdditionalData["rng"]
	t.s.AD(true, []byte("rng"))
	// KEY inserts the key into the state. It also provides forward secrecy.
	t.s.KEY(keyBytes[:])
	return t, nil
}

// ------------------------------- READ OPS --------------------------------- //
// ExtractBytes returns a buffer filled with the verifier's challenge bytes.
// The label parameter is metadata about the challenge, and is also appended to
// the transcript. More derails on "Transcript Protocols" section of Merlin.tool
func (t *Transcript) ExtractBytes(label []byte, outLen int) []byte {
	// AdditionalData[label || le32(outLen)]
	t.s.AD(true, t.appendSizeToLabel(label, outLen))
	// Call the unterlying PRF function to fill a buffer with random bytes.
	outBytes := t.s.PRF(outLen)
	return outBytes
}

// Read reads random data and writes to buf. Implicitly implements io.Reader.
func (t *Transcript) Read(buf []byte) (int, error) {
	// AdditionalData["Read_PRG" || le32(len(buf))]
	t.s.AD(true, t.appendSizeToLabel([]byte("Read_PRG"), len(buf)))
	// PRF(buf)
	res := t.s.PRF(len(buf))
	return copy(buf, res), nil
}

// ------------------------------- AUXILIARY -------------------------------- //
// appendSizeToLabel appends the size of the message to the label.
// The StrobeGo API does not support continuation operations,
// so we have to pass the label and length as a single buffer.
// Otherwise it will record two meta-AD operations instead of one.
func (t *Transcript) appendSizeToLabel(label []byte, outLen int) (labelAndSize []byte) {
	sizeBuffer := make([]byte, 4)
	binary.LittleEndian.PutUint32(sizeBuffer[0:], uint32(outLen))
	labelAndSize = append(label, sizeBuffer...)
	return
}
