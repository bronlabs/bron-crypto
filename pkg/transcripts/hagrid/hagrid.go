package hagrid

import (
	"fmt"
	"io"

	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/transcripts"
)

const (
	protocolLabel        string           = "Hagrid v1.0"
	domainSeparatorLabel string           = "<@>"
	Type                 transcripts.Type = "Hagrid"
)

var hashConstructor = sha3.New256 // Hash function used to hash messages longer than maxUnhashedMessage bytes.

var _ transcripts.Transcript = (*Transcript)(nil)

type Transcript struct {
	s [32]byte
}

// NewTranscript creates a new transcript with the supplied application label. The initial state is a hash of the appLabel.
func NewTranscript(appLabel string) *Transcript {
	t := Transcript{
		s: [32]byte{},
	}
	t.AppendMessages(domainSeparatorLabel, []byte(protocolLabel), []byte(appLabel))
	return &t
}

// Clone returns a copy of the transcript.
func (t *Transcript) Clone() transcripts.Transcript {
	return &Transcript{s: t.s}
}

func (*Transcript) Type() transcripts.Type {
	return Type
}

// -------------------------- WRITE/READ OPS -------------------------------- //
// AppendMessage adds the message to the transcript with the supplied label.
func (t *Transcript) AppendMessages(label string, messages ...[]byte) {
	for _, message := range messages {
		t.appendMessage(label, message)
	}
}

func (t *Transcript) appendMessage(label string, message []byte) {
	// AdditionalData[label]
	t.ratchet([]byte(label))
	t.ratchet(message)
}

// AppendScalars appends a vector of scalars to the transcript, serialising each scalar
// with the label=label_i. If the vector's length is 1, label is used directly.
func (t *Transcript) AppendScalars(label string, scalars ...curves.Scalar) {
	if len(scalars) == 1 {
		t.AppendMessages("curve_name", []byte(scalars[0].CurveName()))
		t.AppendMessages(label, scalars[0].Bytes())
	}
	for i, scalar := range scalars {
		t.AppendMessages(fmt.Sprintf("curve_name_%d", i), []byte(scalar.CurveName()))
		t.AppendMessages(fmt.Sprintf("%s_%d", label, i), scalar.Bytes())
	}
}

// AppendPoints appends a vector of points to the transcript, serialising each
// point to the compressed affine form, with the label=label_i. If the vector's length
// is 1, label is used directly.
func (t *Transcript) AppendPoints(label string, points ...curves.Point) {
	if len(points) == 1 {
		t.AppendMessages("curve_name", []byte(points[0].CurveName()))
		t.AppendMessages(label, points[0].ToAffineCompressed())
	}
	for i, point := range points {
		t.AppendMessages(fmt.Sprintf("curve_name_%d", i), []byte(point.CurveName()))
		t.AppendMessages(fmt.Sprintf("%s_%d", label, i), point.ToAffineCompressed())
	}
}

// ExtractBytes returns a buffer filled with the verifier's challenge bytes.
// The label parameter is metadata about the challenge, and is also appended to
// the transcript.
func (t *Transcript) ExtractBytes(label string, outLen int) []byte {
	// AdditionalData[label]
	t.ratchet([]byte(label))
	// Call the underlying sum function to fill a buffer with random bytes.
	out := make([]byte, outLen)
	cShake := sha3.NewCShake256([]byte(label), []byte(domainSeparatorLabel))
	if _, err := cShake.Write(t.s[:]); err != nil {
		panic(errs.WrapFailed(err, "failed to hash transcript for cShake"))
	}
	if _, err := cShake.Read(out); err != nil {
		panic(errs.WrapFailed(err, "failed to read from cShake"))
	}
	return out
}

// hash hashes the previous transcript state with the supplied message.
func (t *Transcript) ratchet(message []byte) {
	h := hashConstructor()
	h.Write(t.s[:])
	h.Write(message)
	copy(t.s[:], h.Sum(nil))
}

// --------------------------------- PRNG ----------------------------------- //
// Hagrid PRNG provides a transcript-based RNG.
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
// that the sum output has at least as much entropy as the witness does. Finally,
// binding the output to the output of an external RNG provides a backstop and
// avoids the downsides of fully deterministic generation.

// The transcript PRNG has a different type, to make it impossible to accidentally
// rekey the public transcript, or use an RNG before it has been finalised.
type prngReader struct {
	t *Transcript
	io.Reader
}

// NewReader creates a new transcript PRNG, needed to generate random bytes.
// It clones the public transcript state, then re-keys it with both:
//   - The witness data (the secret data that allows you to efficiently verify
//     the veracity of the statement that will use the PRNG randomness).
//   - 32 bytes of entropy from an external RNG arbitrarily chosen.
func (t *Transcript) NewReader(label string, witness []byte, rng io.Reader) (io.Reader, error) {
	// 1. Create a secret clone of the public transcript state
	prng, ok := t.Clone().(*Transcript)
	if !ok {
		return nil, errs.NewInvalidType("not a Transcript")
	}
	// 2. Rekey with witness data
	// KEY[label](witness);
	prng.ratchet([]byte(label))
	prng.ratchet(witness)
	// 3. Rekey with 32 bytes of entropy from an external RNG
	var keyBytes [32]byte // 256 bits
	if _, err := rng.Read(keyBytes[:]); err != nil {
		return nil, errs.WrapFailed(err, "failed to read random bytes for transcript RNG")
	}
	// KEY[b"rng"](rng);
	prng.ratchet([]byte("rng"))
	prng.ratchet(keyBytes[:])
	prngReader := &prngReader{t: prng}
	return prngReader, nil
}

// Read reads random data and writes to buf. Implicitly implements io.Reader.
func (pr *prngReader) Read(buf []byte) (int, error) {
	// AdditionalData["Read_PRG"]
	output := pr.t.ExtractBytes("Read_PRG", len(pr.t.s))
	copy(buf, output)
	return len(buf), nil
}
