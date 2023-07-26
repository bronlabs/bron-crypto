package transcript

import (
	"hash"
	"io"
)

type Transcript interface {
	AppendMessage(label, message []byte, h hash.Hash)
	ExtractBytes(label []byte, outLen int) []byte
	NewPrngReader(witnessLabel, witness []byte, prng io.Reader) (io.Reader, error)
}
