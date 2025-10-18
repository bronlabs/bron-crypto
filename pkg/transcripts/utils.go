package transcripts

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

func Append[T base.BytesLike](tape Transcript, label string, xs ...T) {
	for _, x := range xs {
		tape.AppendBytes(label, x.Bytes())
	}
}

func Extract[T base.BytesLike](tape Transcript, label string, f algebra.FiniteStructure[T]) (T, error) {
	buf, err := tape.ExtractBytes(label, uint(f.ElementSize()+(base.StatisticalSecurityBytesCeil)))
	if err != nil {
		return *new(T), errs.WrapFailed(err, "could not extract bytes from transcript")
	}
	x, err := f.Hash(buf)
	if err != nil {
		return *new(T), errs.WrapFailed(err, "could not extract bytes from transcript")
	}

	return x, nil
}
