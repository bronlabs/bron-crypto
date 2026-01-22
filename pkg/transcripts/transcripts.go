package transcripts

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
)

// Transcript records protocol messages and derives challenges from them.
type Transcript interface {
	AppendDomainSeparator(tag string)
	AppendBytes(label string, messages ...[]byte)
	ExtractBytes(label string, outLen uint) ([]byte, error)
	base.Clonable[Transcript]
}
