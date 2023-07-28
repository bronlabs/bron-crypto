package transcript

import (
	"io"
)

type Transcript interface {
	AppendMessage(label, message []byte) error
	ExtractBytes(label []byte, outLen int) []byte
	NewReader(witnessLabel, witness []byte, prng io.Reader) (io.Reader, error)
	Clone() Transcript
	Type() Type
}

type Type string
