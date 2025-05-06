package transcripts

import (
	"golang.org/x/crypto/sha3"
)

var (
	// TranscriptXofFunction is used in the `transcripts` package for hashing the transcript of a protocol.
	TranscriptXofFunction = sha3.NewShake256
)

type Transcript interface {
	AppendDomainSeparator(tag string)
	AppendBytes(label string, message ...[]byte)
	ExtractBytes(label string, outLen uint) ([]byte, error)
	Clone() Transcript
}
