package hash_comm

import (
	"hash"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"golang.org/x/crypto/blake2b"
)

var (
	_        commitments.Commitment = Commitment{}
	_        commitments.Message    = Message(nil)
	_        commitments.Witness    = Witness{}
	_        commitments.Key        = Key{}
	HmacFunc                        = blake2b.New256
)

const (
	DigestSize                  = 32
	Name       commitments.Name = "KMACBasedCommitmentScheme"
)

type (
	Commitment [DigestSize]byte
	Message    []byte
	Witness    [DigestSize]byte
	Key        [DigestSize]byte
)

func (c Commitment) Bytes() []byte {
	return c[:]
}

func (w Witness) Bytes() []byte {
	return w[:]
}

func NewKeyFromCRSBytes(sid network.SID, dst string, crs ...[]byte) (Key, error) {
	if ct.SliceIsZero(sid[:]) == 1 {
		return *new(Key), errs.NewArgument("SID cannot be zero")
	}
	if dst == "" {
		return *new(Key), errs.NewArgument("dst cannot be empty")
	}
	hasher, err := blake2b.New256(sid[:])
	if err != nil {
		return *new(Key), errs.WrapFailed(err, "cannot create hash")
	}
	h := func() hash.Hash { return hasher }
	out, err := hashing.HashPrefixedLength(h, append(crs, []byte(dst))...)
	if err != nil {
		return *new(Key), errs.WrapFailed(err, "cannot hash CRS")
	}
	var key [DigestSize]byte
	copy(key[:], out)
	return key, nil
}

func NewScheme(key Key) (*Scheme, error) {
	if ct.SliceIsZero(key[:]) == 1 {
		return nil, errs.NewArgument("key cannot be zero")
	}
	hmac, err := HmacFunc(key[:])
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create HMAC hash function")
	}
	return &Scheme{hmac: hmac}, nil
}

type Scheme struct {
	hmac hash.Hash
}

func (s *Scheme) Name() commitments.Name {
	return Name
}
func (s *Scheme) Committer() commitments.Committer[Witness, Message, Commitment] {
	return &Committer{s.hmac}
}
func (s *Scheme) Verifier() commitments.Verifier[Witness, Message, Commitment] {
	committingParty := &Committer{s.hmac}
	generic := commitments.NewGenericVerifier(committingParty, func(c1, c2 Commitment) bool {
		return ct.SliceEqual(c1[:], c2[:]) == 1
	})
	out := &Verifier{GenericVerifier: *generic}
	return out
}

type Committer struct {
	hmac hash.Hash
}

func (c *Committer) CommitWithWitness(message Message, witness Witness) (commitment Commitment, err error) {
	c.hmac.Write(witness[:])
	c.hmac.Write(message)
	out := c.hmac.Sum(nil)
	c.hmac.Reset()
	if len(out) != DigestSize {
		return commitment, errs.NewHashing("invalid commitment length, expected 64 bytes, got %d", len(out))
	}
	copy(commitment[:], out)
	return commitment, nil
}

func (c *Committer) Commit(message Message, prng io.Reader) (commitment Commitment, witness Witness, err error) {
	if _, err = io.ReadFull(prng, witness[:]); err != nil {
		return commitment, witness, errs.WrapRandomSample(err, "cannot sample witness")
	}

	commitment, err = c.CommitWithWitness(message, witness)
	if err != nil {
		return Commitment{}, Witness{}, errs.WrapFailed(err, "cannot compute commitment")
	}

	return commitment, witness, nil
}

type Verifier struct {
	commitments.GenericVerifier[*Committer, Witness, Message, Commitment]
}
