package simple

import (
	"encoding/binary"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
	"golang.org/x/crypto/sha3"
	"io"
)

const (
	domainId  = "domain-"
	appendId  = "append-"
	extractId = "extract-"
)

type transcript struct {
	h sha3.ShakeHash
}

func NewTranscript(domainSeparator string) transcripts.Transcript {
	t := &transcript{h: sha3.NewShake256()}
	t.AppendDomainSeparator(domainSeparator)
	return t
}

func (t *transcript) AppendDomainSeparator(tag string) {
	_, _ = t.h.Write([]byte(domainId))
	_, _ = t.h.Write(binary.BigEndian.AppendUint64(nil, uint64(len(tag))))
	_, _ = t.h.Write([]byte(tag))
}

func (t *transcript) AppendBytes(label string, messages ...[]byte) {
	_, _ = t.h.Write([]byte(appendId))
	_, _ = t.h.Write(binary.BigEndian.AppendUint64(nil, uint64(len(label))))
	_, _ = t.h.Write([]byte(label))
	_, _ = t.h.Write(binary.BigEndian.AppendUint64(nil, uint64(len(messages))))
	for _, message := range messages {
		_, _ = t.h.Write(binary.BigEndian.AppendUint64(nil, uint64(len(message))))
		_, _ = t.h.Write(message)
	}
}

func (t *transcript) ExtractBytes(label string, outLen uint) ([]byte, error) {
	_, _ = t.h.Write([]byte(extractId))
	_, _ = t.h.Write(binary.BigEndian.AppendUint64(nil, uint64(len(label))))
	_, _ = t.h.Write([]byte(label))
	_, _ = t.h.Write(binary.BigEndian.AppendUint64(nil, uint64(outLen)))
	hClone := t.h.Clone()

	buf := make([]byte, outLen)
	_, err := io.ReadFull(t.h, buf)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not read from transcript")
	}

	t.h = hClone
	return buf, err
}

func (t *transcript) Clone() transcripts.Transcript {
	h := t.h.Clone()
	return &transcript{h}
}
