package hagrid

import (
	"encoding/binary"
	"io"

	"golang.org/x/crypto/sha3"

	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

// Keep the tag at constant length.
type tag byte

const (
	customizedShakeName = "BRON_CRYPTO_HAGRID_TRANSCRIPT-"

	domainTag tag = iota + 0xa0
	appendTag
	extractTag
	extractedTag
	continuedTag
)

type transcript struct {
	h sha3.ShakeHash
}

// NewTranscript returns a transcript instance bound to the provided protocol name.
func NewTranscript(name string) transcripts.Transcript {
	t := &transcript{h: sha3.NewCShake256(nil, []byte(customizedShakeName+name))}
	return t
}

// AppendDomainSeparator adds a domain separator tag to the transcript.
func (t *transcript) AppendDomainSeparator(domainSeparatorTag string) {
	_, _ = t.h.Write([]byte{byte(domainTag)})
	_, _ = t.h.Write(binary.BigEndian.AppendUint64(nil, uint64(len(domainSeparatorTag))))
	_, _ = t.h.Write([]byte(domainSeparatorTag))
}

// AppendBytes appends labelled message bytes to the transcript.
func (t *transcript) AppendBytes(label string, messages ...[]byte) {
	_, _ = t.h.Write([]byte{byte(appendTag)})
	_, _ = t.h.Write(binary.BigEndian.AppendUint64(nil, uint64(len(label))))
	_, _ = t.h.Write([]byte(label))
	_, _ = t.h.Write(binary.BigEndian.AppendUint64(nil, uint64(len(messages))))
	for _, message := range messages {
		_, _ = t.h.Write(binary.BigEndian.AppendUint64(nil, uint64(len(message))))
		_, _ = t.h.Write(message)
	}
}

// ExtractBytes derives outLen bytes from the transcript under the given label.
func (t *transcript) ExtractBytes(label string, outLen uint) ([]byte, error) {
	_, _ = t.h.Write([]byte{byte(extractTag)})
	_, _ = t.h.Write(binary.BigEndian.AppendUint64(nil, uint64(len(label))))
	_, _ = t.h.Write([]byte(label))
	_, _ = t.h.Write(binary.BigEndian.AppendUint64(nil, uint64(outLen)))
	hClone := t.h.Clone()

	// Explicitly fork these transcripts to prevent length extension attacks from being possible
	// (at least, without the additional ability to remove a byte from a finalised hash).
	_, _ = t.h.Write([]byte{byte(continuedTag)})
	_, _ = hClone.Write([]byte{byte(extractedTag)})

	buf := make([]byte, outLen)
	if _, err := io.ReadFull(hClone, buf); err != nil {
		return nil, errs2.Wrap(err).WithMessage("could not read from SHAKE hash")
	}

	return buf, nil
}

// Clone returns a copy of the transcript in its current state.
func (t *transcript) Clone() transcripts.Transcript {
	h := t.h.Clone()
	return &transcript{h}
}
