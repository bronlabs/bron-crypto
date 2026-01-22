package network

import (
	"crypto/sha3"
	"hash"

	"github.com/bronlabs/errs-go/pkg/errs"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
)

var sidHasher = func() hash.Hash { return sha3.New256() }

// SID is a 32-byte session identifier derived from hashed inputs.
type SID [32]byte

// NewSID hashes the provided byte slices to produce a 32-byte session identifier.
func NewSID(xs ...[]byte) (SID, error) {
	digest, err := hashing.Hash(sidHasher, xs...)
	if len(digest) != 32 {
		return SID{}, ErrInvalidArgument.WithMessage("digest length is not 32 bytes")
	}
	if err != nil {
		return SID{}, errs.Wrap(err).WithMessage("failed to create session ID")
	}
	var sid SID
	copy(sid[:], digest)
	return sid, nil
}

// Message represents any network payload.
type Message any
