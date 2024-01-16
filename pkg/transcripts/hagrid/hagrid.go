package hagrid

import (
	"fmt"

	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/csprng"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
)

const (
	// Set the probability of collision to our desired security level.
	collisionResistance = base.ComputationalSecurity
	// Set the state length to twice the collision resistance (birthday paradox).
	stateLength = (2 * collisionResistance) / 8

	protocolLabel        string           = "Hagrid v1.0"
	domainSeparatorLabel string           = "<@>"
	Type                 transcripts.Type = "Hagrid"
)

// Hash function used to chain message hashes.
var TranscriptHashFunction = base.TranscriptHashFunction

var _ transcripts.Transcript = (*Transcript)(nil)

type Transcript struct {
	state [stateLength]byte
	prng  csprng.CSPRNG

	transcripts.Transcript

	_ types.Incomparable
}

// NewTranscript creates a new transcript with the supplied application label. The initial state is a hash of the appLabel.
func NewTranscript(appLabel string, prng csprng.CSPRNG) *Transcript {
	t := Transcript{
		state: [stateLength]byte{},
		prng:  prng,
	}
	t.AppendMessages(domainSeparatorLabel, []byte(protocolLabel), []byte(appLabel))
	return &t
}

// Clone returns a copy of the transcript.
func (t *Transcript) Clone() transcripts.Transcript {
	return &Transcript{state: t.state}
}

func (*Transcript) Type() transcripts.Type {
	return Type
}

/*.-------------------------- WRITE/READ OPS --------------------------------.*/

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
// with the label=label_i.
func (t *Transcript) AppendScalars(label string, scalars ...curves.Scalar) {
	for i, scalar := range scalars {
		t.AppendMessages(fmt.Sprintf("curve_name_%d", i), []byte(scalar.ScalarField().Curve().Name()))
		t.AppendMessages(fmt.Sprintf("%s_%d", label, i), scalar.Bytes())
	}
}

// AppendPoints appends a vector of points to the transcript, serialising each
// point to the compressed affine form, with the label=label_i. If the vector's length
// is 1, label is used directly.
func (t *Transcript) AppendPoints(label string, points ...curves.Point) {
	for i, point := range points {
		t.AppendMessages(fmt.Sprintf("curve_name_%d", i), []byte(point.Curve().Name()))
		t.AppendMessages(fmt.Sprintf("%s_%d", label, i), point.ToAffineCompressed())
	}
}

// ExtractBytes generates outLen bytes of pseudorandom data with its `prng`
// based on the current transcript state and the supplied label. If the `prng`
// is nil, a Shake256 hash is used instead.
func (t *Transcript) ExtractBytes(label string, outLen int) (out []byte, err error) {
	// AdditionalData[label]
	t.ratchet([]byte(label))
	out = make([]byte, outLen)
	if t.prng != nil {
		if err := t.prng.Seed(t.state[:], nil); err != nil {
			return nil, errs.WrapFailed(err, "failed to seed transcript prng")
		}
		if _, err := t.prng.Read(out); err != nil {
			return nil, errs.WrapRandomSampleFailed(err, "failed to read from transcript prng")
		}
	} else {
		shake := sha3.NewShake256()
		if _, err := shake.Write(t.state[:]); err != nil {
			return nil, errs.WrapFailed(err, "failed to write transcript state in shake")
		}
		if _, err := shake.Read(out); err != nil {
			return nil, errs.WrapRandomSampleFailed(err, "failed to read from shake")
		}
	}
	return out, nil
}

// hash hashes the previous transcript state with the supplied message.
func (t *Transcript) ratchet(message []byte) {
	h := TranscriptHashFunction()
	h.Write(t.state[:])
	h.Write(message)
	copy(t.state[:], h.Sum(nil))
}
