package hagrid

import (
	crand "crypto/rand"
	"fmt"
	"io"
	"slices"

	"golang.org/x/crypto/chacha20"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/csprng"
	"github.com/copperexchange/krypton-primitives/pkg/csprng/fkechacha20"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
)

const (
	protocolLabel        string           = "Hagrid v1.0"
	domainSeparatorLabel string           = "<@>"
	transcriptType       transcripts.Type = "Hagrid"
	stateSize                             = base.CollisionResistanceBytes
)

var _ transcripts.Transcript = (*Transcript)(nil)

type Transcript struct {
	state [stateSize]byte
	prng  csprng.CSPRNG
	salt  []byte

	_ ds.Incomparable
}

// NewTranscript creates a new transcript with the supplied application label. The initial state is a hash of the appLabel.
func NewTranscript(appLabel string, prng io.Reader) *Transcript {
	if prng == nil {
		prng = crand.Reader
	}
	salt := bitstring.PadToRight([]byte(appLabel), chacha20.NonceSizeX-len(appLabel))
	var seedablePrng csprng.CSPRNG
	var err error
	seedablePrng, ok := prng.(csprng.CSPRNG)
	if !ok {
		var seed [fkechacha20.ChachaPRNGSecurityStrength]byte
		if _, err := io.ReadFull(prng, seed[:]); err != nil {
			panic(err)
		}
		seedablePrng, err = fkechacha20.NewPrng(seed[:], salt)
		if err != nil {
			panic(err)
		}
	}
	t := Transcript{
		state: [stateSize]byte{},
		prng:  seedablePrng,
		salt:  salt,
	}
	t.AppendMessages(domainSeparatorLabel, []byte(protocolLabel), []byte(appLabel))
	return &t
}

// Clone returns a copy of the transcript.
func (t *Transcript) Clone() transcripts.Transcript {
	seededPrngCopy, err := t.prng.New(nil, nil)
	if err != nil {
		panic(err)
	}
	return &Transcript{
		state: t.state,
		prng:  seededPrngCopy,
	}
}

func (*Transcript) Type() transcripts.Type {
	return transcriptType
}

// AppendMessages adds the message to the transcript with the supplied label.
func (t *Transcript) AppendMessages(label string, messages ...[]byte) {
	for _, message := range messages {
		t.appendMessage(label, message)
	}
}

func (t *Transcript) appendMessage(label string, message []byte) {
	_ = t.ratchet([]byte(label))
	_ = t.ratchet(message)
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
func (t *Transcript) ExtractBytes(label string, outLen uint) (out []byte, err error) {
	if err := t.ratchet([]byte(label)); err != nil {
		return nil, errs.WrapFailed(err, "cannot update state")
	}
	out = make([]byte, outLen)
	if t.prng == nil {
		return nil, errs.NewIsNil("prng is nil")
	}
	if err := t.prng.Seed(t.state[:], t.salt); err != nil {
		return nil, errs.WrapFailed(err, "failed to seed transcript prng")
	}
	if _, err := io.ReadFull(t.prng, out); err != nil {
		return nil, errs.WrapRandomSample(err, "failed to read from transcript prng")
	}
	return out, nil
}

// Bind appends the sessionId to the transcript using dst as domain-separation
// tag and extracts a fresh transcript-bound sessionId `sid`. If the transcript is nil, a new
// one is created with the supplied `dst` label.
func (t *Transcript) Bind(sessionId []byte, dst string) (boundSessionId []byte, err error) {
	t.AppendMessages(dst, sessionId)
	boundSessionId, err = t.ExtractBytes(dst, stateSize)
	if err != nil {
		return nil, errs.WrapHashing(err, "couldn't extract boundSessionId from transcript")
	}
	return boundSessionId, nil
}

// ratchet hashes the previous transcript state with the supplied message.
func (t *Transcript) ratchet(message []byte) error {
	h := transcripts.TranscriptXofFunction()
	if _, err := h.Write(slices.Concat(t.state[:], message)); err != nil {
		return errs.WrapHashing(err, "cannot create digest")
	}

	newState := make([]byte, stateSize)
	if _, err := io.ReadFull(h, newState); err != nil {
		return errs.WrapHashing(err, "cannot create digest")
	}

	copy(t.state[:], newState)
	return nil
}
