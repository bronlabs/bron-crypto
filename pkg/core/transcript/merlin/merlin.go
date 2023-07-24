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

// -------------------------- WRITE/READ OPS -------------------------------- //
// Append adds the message to the transcript with the supplied label.
func (t *Transcript) AppendMessage(label, message []byte) {
	// AdditionalData[label || le32(len(message))]
	t.s.AD(true, appendSizeToLabel(label, len(message)))
	// AdditionalData[message]
	t.s.AD(false, message)
}

// AppendHashedMessage adds the hash of the message to the transcript with the
// supplied label. The hash function is passed as a parameter.
func (t *Transcript) AppendHashedMessage(label, message []byte, h hash.Hash) (err error) {
	// Hash message
	if _, err := h.Write(message); err != nil {
		return errs.WrapFailed(err, "failed to hash message for transcript")
	}
	// AdditionalData[label || le32(len(message))]
	t.s.AD(true, appendSizeToLabel(label, len(message)))
	// Append hash to transcript
	t.s.AD(false, h.Sum(nil))
	return nil
}

// ExtractBytes returns a buffer filled with the verifier's challenge bytes.
// The label parameter is metadata about the challenge, and is also appended to
// the transcript. More derails on "Transcript Protocols" section of Merlin.tool
func (t *Transcript) ExtractBytes(label []byte, outLen int) []byte {
	// AdditionalData[label || le32(outLen)]
	t.s.AD(true, appendSizeToLabel(label, outLen))
	// Call the unterlying PRF function to fill a buffer with random bytes.
	outBytes := t.s.PRF(outLen)
	return outBytes
}

// --------------------------------- PRNG ----------------------------------- //
// Merlin provides a transcript-based RNG (https://merlin.cool/transcript/rng.html).
// To generate randomness, a prover:
//  1. creates a secret clone of the public transcript state up to that point, so
//     that the RNG output is bound to the entire public transcript;
//  2. rekeys their clone with their secret witness data, so that the RNG output
//     is bound to their secrets;
//  3. rekeys their clone with 32 bytes of entropy from an external RNG, avoiding
//     fully deterministic proofs.

// The transcript RNG has a different type, to make it impossible to accidentally
// rekey the public transcript, or use an RNG before it has been finalized.
type TranscriptPRNG struct {
	s strobe.Strobe
}

// NewTranscriptPRNG creates a new transcript PRNG. It clones the public transcript
// state, re-keys it with the witness data, and re-keys it with 32 bytes of entropy
// from an external RNG. The resulting RNG can be used to generate random bytes.
func (t *Transcript) NewTranscriptPRNG(witnessLabel, witness []byte, rng io.Reader) (*TranscriptPRNG, error) {
	// 1. Create a secret clone of the public transcript state
	transcriptPRNG := &TranscriptPRNG{s: *t.s.Clone()}
	// 2. Rekey with witness data
	//	  STROBE: KEY[label || LE32(witness.len())](witness);
	transcriptPRNG.s.AD(true, appendSizeToLabel(witnessLabel, len(witness)))
	transcriptPRNG.s.KEY(witness)
	// 3. Rekey with 32 bytes of entropy from an external RNG
	var keyBytes [32]byte // 256 bits
	if _, err := rng.Read(keyBytes[:]); err != nil {
		return nil, errs.WrapFailed(err, "failed to read random bytes for transcript RNG")
	}
	//    STROBE:  KEY[b"rng"](rng);
	transcriptPRNG.s.AD(true, []byte("rng"))
	transcriptPRNG.s.KEY(keyBytes[:])
	return transcriptPRNG, nil
}

// Read reads random data and writes to buf. Implicitly implements io.Reader.
func (t *TranscriptPRNG) Read(buf []byte) (int, error) {
	// AdditionalData["Read_PRG" || le32(len(buf))]
	t.s.AD(true, appendSizeToLabel([]byte("ReadRNG"), len(buf)))
	// PRF(buf)
	res := t.s.PRF(len(buf))
	return copy(buf, res), nil
}

// ------------------------------- AUXILIARY -------------------------------- //
// appendSizeToLabel appends the size of the message to the label.
// The StrobeGo API does not support continuation operations,
// so we have to pass the label and length as a single buffer.
// Otherwise it will record two meta-AD operations instead of one.
func appendSizeToLabel(label []byte, outLen int) (labelAndSize []byte) {
	sizeBuffer := make([]byte, 4)
	binary.LittleEndian.PutUint32(sizeBuffer[0:], uint32(outLen))
	labelAndSize = append(label, sizeBuffer...)
	return
}
