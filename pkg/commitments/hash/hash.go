package hash_comm

import (
	"bytes"
	"io"

	"golang.org/x/crypto/blake2b"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"github.com/bronlabs/errs-go/errs"
)

var (
	// HmacFunc defines the hash function used to instantiate the HMAC-based commitments.
	HmacFunc = blake2b.New256
)

const (
	KeySize    = 32
	DigestSize = 32

	// Name identifies the hash-based commitment scheme.
	Name commitments.Name = "HashCommitment"
)

type (
	// Commitment is the hash digest produced by the commitment algorithm.
	Commitment [DigestSize]byte
	// Message is an arbitrary byte slice being committed.
	Message = []byte
	// Witness is the random nonce mixed into the commitment.
	Witness [DigestSize]byte
)

func (c Commitment) Equal(other Commitment) bool {
	return bytes.Equal(c[:], other[:])
}

func (w Witness) Equal(other Witness) bool {
	return ct.SliceEqual(w[:], other[:]) == ct.True
}

func NewCommitment(v []byte) (Commitment, error) {
	if len(v) != DigestSize {
		return Commitment{}, errs.New("invalid commitment length")
	}
	var c Commitment
	copy(c[:], v)
	return c, nil
}

func NewWitness(v []byte) (Witness, error) {
	if len(v) != DigestSize {
		return Witness{}, errs.New("invalid witness length")
	}
	var w Witness
	copy(w[:], v)
	return w, nil
}

func SampleWitness(prng io.Reader) (Witness, error) {
	if prng == nil {
		return Witness{}, commitments.ErrIsNil.WithMessage("prng must not be nil")
	}
	var w Witness
	if _, err := io.ReadFull(prng, w[:]); err != nil {
		return Witness{}, errs.Wrap(err).WithMessage("could not sample witness")
	}
	return w, nil
}
