package hashcom

import (
	"bytes"
	"hash"
	"io"

	"golang.org/x/crypto/blake2b"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
)

var (
	// hmacFunc is the keyed hash that realises the commitment. blake2b.New256
	// keyed with the CommitmentKey acts as a MAC via BLAKE2b's native keyed mode
	// (not the nested HMAC construction, despite the name). Its collision
	// resistance is what binding reduces to, and its pseudo-randomness over the
	// secret witness is what makes the scheme hiding.
	hmacFunc = blake2b.New256
)

// HashFunc is the unkeyed variant of the internal hmac used in commitments.
func HashFunc() hash.Hash {
	h, _ := hmacFunc(nil) // there won't be an error if key is nil.
	return h
}

const (
	// KeySize is the length in bytes of a CommitmentKey, used directly as the
	// BLAKE2b key.
	KeySize = 32
	// DigestSize is the length in bytes of a Commitment and of a Witness, equal
	// to the BLAKE2b-256 output. At 256 bits it provides base.CollisionResistance
	// (2λ) bits, i.e. λ=128 bits of binding security against birthday collisions.
	DigestSize = 32

	// Name identifies the hash-based commitment scheme.
	Name commitments.Name = "HashCommitment"
)

type (
	// Commitment is the keyed-hash digest published as the binding commitment. It
	// is public and reveals nothing about the message until the witness is opened.
	Commitment [DigestSize]byte
	// Message is the arbitrary byte string being committed.
	Message = []byte
	// Witness is the secret random nonce mixed into the commitment. It must be kept
	// private until opening: revealing it (or reusing it) destroys hiding.
	Witness [DigestSize]byte
)

// Equal reports whether two commitments are byte-identical. Commitments are
// public values, so a variable-time comparison leaks nothing sensitive.
func (c Commitment) Equal(other Commitment) bool {
	return bytes.Equal(c[:], other[:])
}

// Equal reports whether two witnesses are byte-identical, in constant time. The
// witness is the secret opening randomness, so the comparison must not reveal it
// (or how it differs) through a timing side channel.
func (w Witness) Equal(other Witness) bool {
	return ct.SliceEqual(w[:], other[:]) == ct.True
}

// SampleWitness draws a fresh DigestSize-byte opening nonce from prng. These bits
// are the sole source of the scheme's hiding, so prng must be a cryptographically
// secure source; a reused or low-entropy witness lets an adversary recover the
// committed message by re-deriving the commitment.
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

func init() { //nolint:gochecknoinits // sanity check that the chosen parameters meet the security requirements
	h, _ := hmacFunc(nil)
	if DigestSize != h.Size() {
		panic("DigestSize must match the output size of the hash function")
	}
	digestBits := h.Size() * 8 // 256
	if digestBits < base.CollisionResistance {
		panic("DigestSize must be at least CollisionResistance bits to achieve the desired security level")
	}
}
