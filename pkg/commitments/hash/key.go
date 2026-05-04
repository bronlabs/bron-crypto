package hash_comm

import (
	"bytes"
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"github.com/bronlabs/bron-crypto/pkg/commitments/internal"
	ts "github.com/bronlabs/bron-crypto/pkg/transcripts"
)

func SampleCommitmentKey(prng io.Reader) (*CommitmentKey, error) {
	if prng == nil {
		return nil, commitments.ErrIsNil.WithMessage("prng must not be nil")
	}
	var k CommitmentKey
	if _, err := io.ReadFull(prng, k[:]); err != nil {
		return nil, errs.Wrap(err).WithMessage("could not sample commitment key")
	}
	return &k, nil
}

func ExtractCommitmentKey(transcript ts.Transcript, label string) (*CommitmentKey, error) {
	if transcript == nil || label == "" {
		return nil, commitments.ErrIsNil.WithMessage("transcript and label must not be nil")
	}
	bs, err := transcript.ExtractBytes(label, KeySize)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not extract commitment key from transcript")
	}
	var out CommitmentKey
	copy(out[:], bs)
	return &out, nil
}

type CommitmentKey [KeySize]byte

func (k *CommitmentKey) SampleWitness(prng io.Reader) (Witness, error) {
	out, err := SampleWitness(prng)
	if err != nil {
		return Witness{}, errs.Wrap(err).WithMessage("could not sample witness")
	}
	return out, nil
}

func (k *CommitmentKey) CommitWithWitness(message Message, witness Witness) (Commitment, error) {
	if k == nil {
		return Commitment{}, commitments.ErrIsNil.WithMessage("commitment key must not be nil")
	}
	h, err := HmacFunc(k[:])
	if err != nil {
		return Commitment{}, errs.Wrap(err).WithMessage("could not create hash function")
	}
	// length prefixing is not necessary because witness is fixed size so encoded message is unambiguous.
	h.Write(message)
	h.Write(witness[:])
	return Commitment(h.Sum(nil)), nil
}

func (k *CommitmentKey) Open(commitment Commitment, message Message, witness Witness) error {
	if k == nil {
		return commitments.ErrIsNil.WithMessage("commitment key must not be nil")
	}
	if err := internal.GenericOpen(k, commitment, message, witness); err != nil {
		return errs.Wrap(err).WithMessage("could not open commitment")
	}
	return nil
}

func (k *CommitmentKey) Equal(other *CommitmentKey) bool {
	if k == nil || other == nil {
		return k == other
	}
	return bytes.Equal(k[:], other[:])
}
