package transcripts

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
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
