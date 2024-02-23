package transcripts

import (
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
)

var (
	// TranscriptXofFunction is used in the `transcripts` package for hashing the transcript of a protocol.
	TranscriptXofFunction = sha3.NewShake256
)

type Transcript interface {
	AppendMessages(label string, message ...[]byte)
	AppendScalars(label string, scalars ...curves.Scalar)
	AppendPoints(label string, points ...curves.Point)
	ExtractBytes(label string, outLen uint) ([]byte, error)
	Clone() Transcript
	Type() Type
}

type Type string
