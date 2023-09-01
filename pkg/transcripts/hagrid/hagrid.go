package hagrid

import (
	"fmt"

	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
	"github.com/copperexchange/knox-primitives/pkg/transcripts"
)

const (
	protocolLabel        string           = "Hagrid v1.0"
	domainSeparatorLabel string           = "<@>"
	Type                 transcripts.Type = "Hagrid"
)

var hashConstructor = sha3.New256 // Hash function used to hash messages

var _ transcripts.Transcript = (*Transcript)(nil)

type Transcript struct {
	s [32]byte
	transcripts.Transcript

	_ helper_types.Incomparable
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
		panic(errs.WrapRandomSampleFailed(err, "failed to read from cShake"))
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
