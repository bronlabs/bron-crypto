package transcripts

import (
	"io"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
)

type Transcript interface {
	AppendMessage(label, message []byte)
	AppendScalars(label []byte, scalars ...curves.Scalar)
	AppendPoints(label []byte, points ...curves.Point)
	ExtractBytes(label []byte, outLen int) []byte
	NewReader(witnessLabel, witness []byte, prng io.Reader) (io.Reader, error)
	Clone() Transcript
	Type() Type
}

type Type string
