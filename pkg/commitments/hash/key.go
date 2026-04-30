package hash_comm

import (
	"bytes"
	"hash"
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"github.com/bronlabs/bron-crypto/pkg/commitments/internal"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	ts "github.com/bronlabs/bron-crypto/pkg/transcripts"
)

func SampleCommitmentKey(prng io.Reader) (CommitmentKey, error) {
	if prng == nil {
		return CommitmentKey{}, commitments.ErrIsNil.WithMessage("prng must not be nil")
	}
	var k CommitmentKey
	if _, err := io.ReadFull(prng, k[:]); err != nil {
		return CommitmentKey{}, errs.Wrap(err).WithMessage("could not sample commitment key")
	}
	return k, nil
}

func ExtractCommitmentKey(transcript ts.Transcript, label string) (CommitmentKey, error) {
	if transcript == nil || label == "" {
		return CommitmentKey{}, commitments.ErrIsNil.WithMessage("transcript and label must not be nil")
	}
	out, err := transcript.ExtractBytes(label, KeySize)
	if err != nil {
		return CommitmentKey{}, errs.Wrap(err).WithMessage("could not extract commitment key from transcript")
	}
	return CommitmentKey(out), nil
}

type CommitmentKey [KeySize]byte

func (k CommitmentKey) SampleWitness(prng io.Reader) (Witness, error) {
	return SampleWitness(prng)
}

func (k CommitmentKey) CommitWithWitness(message Message, witness Witness) (Commitment, error) {
	h, err := HmacFunc(k[:])
	if err != nil {
		return Commitment{}, errs.Wrap(err).WithMessage("could not create hash function")
	}
	out, err := hashing.HashIndexLengthPrefixed(func() hash.Hash { return h }, message, witness[:])
	if err != nil {
		return Commitment{}, errs.Wrap(err).WithMessage("could not compute commitment")
	}
	return Commitment(out), nil
}

func (k CommitmentKey) Open(commitment Commitment, message Message, witness Witness) error {
	if err := internal.GenericOpen(k, commitment, message, witness); err != nil {
		return errs.Wrap(err).WithMessage("could not open commitment")
	}
	return nil
}

func (k CommitmentKey) Equal(other CommitmentKey) bool {
	return bytes.Equal(k[:], other[:])
}
