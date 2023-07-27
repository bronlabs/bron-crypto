package transcript

import (
	"hash"
	"io"
	"reflect"
)

type Transcript interface {
	AppendMessage(label, message []byte, h hash.Hash) error
	ExtractBytes(label []byte, outLen int) []byte
	NewPrngReader(witnessLabel, witness []byte, prng io.Reader) (io.Reader, error)
	Clone() Transcript
	Type() reflect.Type
}
