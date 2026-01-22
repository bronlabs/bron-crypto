package transcripts

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/errs-go/pkg/errs"
)

// Append writes BytesLike values to the transcript under the given label.
func Append[T base.BytesLike](tape Transcript, label string, xs ...T) {
	for _, x := range xs {
		tape.AppendBytes(label, x.Bytes())
	}
}

// Extract derives a field element from the transcript using the given structure.
func Extract[T base.BytesLike](tape Transcript, label string, f algebra.FiniteStructure[T]) (T, error) {
	buf, err := tape.ExtractBytes(label, uint(f.ElementSize()+(base.StatisticalSecurityBytesCeil)))
	if err != nil {
		return *new(T), errs.Wrap(err).WithMessage("could not extract bytes from transcript")
	}
	x, err := f.Hash(buf)
	if err != nil {
		return *new(T), errs.Wrap(err).WithMessage("could not extract bytes from transcript")
	}

	return x, nil
}
