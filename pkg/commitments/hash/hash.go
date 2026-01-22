package hash_comm

import (
	"hash"
	"io"

	"golang.org/x/crypto/blake2b"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/errs-go/errs"
)

var (
	_ commitments.Commitment[Commitment] = Commitment{}
	_ commitments.Message                = Message(nil)
	_ commitments.Witness                = Witness{}
	_ commitments.Key                    = Key{}

	// HmacFunc defines the hash function used to instantiate the HMAC-based commitments.
	HmacFunc = blake2b.New256
)

const (
	KeySize    = 32
	DigestSize = 32

	// Name identifies the hash-based commitment scheme.
	Name commitments.Name = "KMACBasedCommitmentScheme"
)

type (
	// Commitment is the hash digest produced by the commitment algorithm.
	Commitment [DigestSize]byte
	// Message is an arbitrary byte slice being committed.
	Message []byte
	// Witness is the random nonce mixed into the commitment.
	Witness [DigestSize]byte
	// Key is the secret HMAC key derived from the CRS.
	Key [KeySize]byte
)

// Bytes returns the raw commitment digest bytes.
func (c Commitment) Bytes() []byte {
	return c[:]
}

func (c Commitment) Equal(other Commitment) bool {
	return ct.SliceEqual(c[:], other[:]) == 1
}

// Bytes returns the raw witness bytes.
func (w Witness) Bytes() []byte {
	return w[:]
}

func (k Key) hmacInit() hash.Hash {
	hmac, err := HmacFunc(k[:])
	if err != nil {
		panic(errs.Wrap(err).WithMessage("cannot create HMAC hash function"))
	}
	return hmac
}

// NewKeyFromCRSBytes derives a commitment key from the SID, domain separation tag and CRS transcripts.
func NewKeyFromCRSBytes(sid network.SID, dst string, crs ...[]byte) (Key, error) {
	if ct.SliceIsZero(sid[:]) == 1 {
		return Key{}, ErrInvalidArgument.WithMessage("SID cannot be zero")
	}
	if dst == "" {
		return Key{}, ErrInvalidArgument.WithMessage("dst cannot be empty")
	}
	hasher, err := blake2b.New256(sid[:])
	if err != nil {
		return Key{}, errs.Wrap(err).WithMessage("cannot create hash")
	}
	h := func() hash.Hash { return hasher }
	out, err := hashing.HashPrefixedLength(h, append(crs, []byte(dst))...)
	if err != nil {
		return Key{}, errs.Wrap(err).WithMessage("cannot hash CRS")
	}
	var key Key
	copy(key[:], out)
	return key, nil
}

// NewScheme constructs the hash-based commitment scheme with the provided key.
func NewScheme(key Key) (*Scheme, error) {
	if ct.SliceIsZero(key[:]) == 1 {
		return nil, ErrInvalidArgument.WithMessage("key cannot be zero")
	}
	return &Scheme{key: key}, nil
}

// Scheme bundles the hash-based committer and verifier using a shared key.
type Scheme struct {
	key Key
}

// Name returns the identifier of the hash-based commitment scheme.
func (*Scheme) Name() commitments.Name {
	return Name
}

// Committer returns a committer initialised with the scheme key.
func (s *Scheme) Committer(opts ...CommitterOption) (*Committer, error) {
	committer := &Committer{s.key.hmacInit()}
	for _, opt := range opts {
		if err := opt(committer); err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot apply committer option")
		}
	}
	return committer, nil
}

// Verifier returns a verifier compatible with commitments produced by the scheme.
func (s *Scheme) Verifier(opts ...VerifierOption) (*Verifier, error) {
	committingParty := &Committer{s.key.hmacInit()}
	generic := commitments.NewGenericVerifier(committingParty)
	out := &Verifier{GenericVerifier: *generic}
	for _, opt := range opts {
		if err := opt(out); err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot apply verifier option")
		}
	}
	return out, nil
}

// Key returns the scheme key material.
func (s *Scheme) Key() Key {
	return s.key
}

// CommitterOption is a functional option for configuring committers.
type CommitterOption = func(*Committer) error

// Committer computes hash-based commitments with an HMAC keyed by the CRS output.
type Committer struct {
	hmac hash.Hash
}

// CommitWithWitness commits to the message using caller-supplied witness randomness.
func (c *Committer) CommitWithWitness(message Message, witness Witness) (commitment Commitment, err error) {
	c.hmac.Write(witness[:])
	c.hmac.Write(message)
	out := c.hmac.Sum(nil)
	c.hmac.Reset()
	if len(out) != DigestSize {
		return commitment, ErrFailed.WithMessage("invalid commitment length, expected %d bytes, got %d", DigestSize, len(out))
	}
	copy(commitment[:], out)
	return commitment, nil
}

// Commit samples fresh witness randomness and computes a commitment to the message.
func (c *Committer) Commit(message Message, prng io.Reader) (commitment Commitment, witness Witness, err error) {
	if _, err = io.ReadFull(prng, witness[:]); err != nil {
		return commitment, witness, errs.Wrap(err).WithMessage("cannot sample witness")
	}

	commitment, err = c.CommitWithWitness(message, witness)
	if err != nil {
		return Commitment{}, Witness{}, errs.Wrap(err).WithMessage("cannot compute commitment")
	}

	return commitment, witness, nil
}

// VerifierOption is a functional option for configuring verifiers.
type VerifierOption = func(*Verifier) error

// Verifier checks commitments against provided messages and witnesses.
type Verifier struct {
	commitments.GenericVerifier[*Committer, Witness, Message, Commitment]
}
