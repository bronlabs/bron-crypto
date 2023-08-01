package merlin

import (
	"crypto/sha256"
	"encoding/binary"
	"io"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/transcript"
	"github.com/mimoo/StrobeGo/strobe"
)

const (
	merlinProtocolLabel    string          = "Merlin v1.1"
	domainSeparatorLabel   string          = "<@>"
	Type                   transcript.Type = "Merlin"
	securityParameter      int             = 256
	maxUnhashedMessageSize int             = 100 * 1024 * 1024 // Messages beyond this size (100MB) are hashed.
)

var hashConstructor = sha256.New // Hash function used to hash messages longer than maxUnhashedMessage bytes.

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
func (t *Transcript) Clone() transcript.Transcript {
	s := t.s.Clone()
	return &Transcript{s: *s}
}

func (t *Transcript) Type() transcript.Type {
	return Type
}

// -------------------------- WRITE/READ OPS -------------------------------- //
// Append adds the message to the transcript with the supplied label. Messages
// of length greater than 100 MB must be hashed.
func (t *Transcript) AppendMessage(label, message []byte) error {
	// AdditionalData[label || le32(len(message))]
	t.s.AD(true, appendSizeToLabel(label, len(message)))
	// If the message is longer than 100 MB, it must be hashed.
	if len(message) > maxUnhashedMessageSize {
		h := hashConstructor() // Create a local hash function.
		if _, err := h.Write(message); err != nil {
			errs.WrapFailed(err, "failed to hash message for Merlin transcript")
		}
		// AdditionalData[h(message)]
		t.s.AD(false, h.Sum(nil))
	} else {
		// AdditionalData[message]
		t.s.AD(false, message)
	}
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
// Binding the output to the transcript state ensures that two different proof
// contexts always generate different outputs. This prevents repeating blinding
// factors between proofs. Binding the output to the prover's witness data ensures
// that the PRF output has at least as much entropy as the witness does. Finally,
// binding the output to the output of an external RNG provides a backstop and
// avoids the downsides of fully deterministic generation.

// The transcript PRNG has a different type, to make it impossible to accidentally
// rekey the public transcript, or use an RNG before it has been finalized.
type prngReader struct {
	t *Transcript
}

// NewReader creates a new transcript PRNG, needed to generate random bytes.
// It clones the public transcript state, then re-keys it with both:
//   - The witness data (the secret data that allows you to efficiently verify
//     the veracity of the statement that will use the PRNG randomness).
//   - 32 bytes of entropy from an external RNG arbitrarily chosen.
func (t *Transcript) NewReader(witnessLabel, witness []byte, rng io.Reader) (io.Reader, error) {
	// 1. Create a secret clone of the public transcript state
	prng := t.Clone().(*Transcript)
	// 2. Rekey with witness data
	//	  STROBE: KEY[label || LE32(witness.len())](witness);
	prng.s.AD(true, appendSizeToLabel(witnessLabel, len(witness)))
	prng.s.KEY(witness)
	// 3. Rekey with 32 bytes of entropy from an external RNG
	var keyBytes [32]byte // 256 bits
	if _, err := rng.Read(keyBytes[:]); err != nil {
		return nil, errs.WrapFailed(err, "failed to read random bytes for transcript RNG")
	}
	//    STROBE:  KEY[b"rng"](rng);
	prng.s.AD(true, []byte("rng"))
	prng.s.KEY(keyBytes[:])
	prngReader := &prngReader{t: prng}
	return prngReader, nil
}

// Read reads random data and writes to buf. Implicitly implements io.Reader.
func (pr *prngReader) Read(buf []byte) (int, error) {
	// AdditionalData["Read_PRG" || le32(len(buf))]
	pr.t.s.AD(true, appendSizeToLabel([]byte("ReadRNG"), len(buf)))
	// PRF(buf)
	res := pr.t.s.PRF(len(buf))
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
