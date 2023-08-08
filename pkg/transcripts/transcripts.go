package transcripts

import (
	"io"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
)

type Transcript interface {
	AppendMessages(label string, message ...[]byte)
	AppendScalars(label string, scalars ...curves.Scalar)
	AppendPoints(label string, points ...curves.Point)
	ExtractBytes(label string, outLen int) []byte
	NewReader(label string, witness []byte, prng io.Reader) (io.Reader, error)
	Clone() Transcript
	Type() Type
}

type Type string
