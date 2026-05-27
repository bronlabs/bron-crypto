package hashcom

import (
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"github.com/bronlabs/bron-crypto/pkg/commitments/internal"
	ts "github.com/bronlabs/bron-crypto/pkg/transcripts"
)

// SampleCommitmentKey draws a uniformly random commitment key from prng. The key
// is a public parameter (it keys the hash, like a common reference string), not a
// secret: binding and hiding both hold against an adversary who knows it, so it
// may be published or shared. Returns an error if prng is nil or supplies fewer
// than KeySize bytes.
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

// ExtractCommitmentKey derives a commitment key deterministically from a public
// transcript under the given label. This binds the key to the protocol context
// (Fiat–Shamir style) so all parties agree on the same public parameter without a
// separate setup, and the label domain-separates it from other extractions on the
// same transcript. The result is public and carries the same trust properties as
// the transcript that produced it.
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

// CommitmentKey is the public parameter that keys the hash commitment. It is not
// a secret and not a trapdoor: publishing it leaves the scheme binding (collision
// resistance of the keyed hash) and hiding (the random witness). Obtain one via
// SampleCommitmentKey or ExtractCommitmentKey; a CBOR-decoded value is accepted
// only when it is exactly KeySize bytes.
type CommitmentKey [KeySize]byte

// Type returns the scheme identifier Name.
func (*CommitmentKey) Type() commitments.Name {
	return Name
}

// SampleWitness draws a fresh opening nonce for use with this key; see the
// package-level SampleWitness for the entropy requirements that hiding depends on.
func (*CommitmentKey) SampleWitness(prng io.Reader) (Witness, error) {
	out, err := SampleWitness(prng)
	if err != nil {
		return Witness{}, errs.Wrap(err).WithMessage("could not sample witness")
	}
	return out, nil
}

// CommitWithWitness deterministically computes the commitment H_k(message ||
// witness) under the keyed hash. The fixed-size witness is appended last, so the
// boundary between message and witness is unambiguous and the encoding is
// injective; this is what lets binding rest on collision resistance alone. Hiding
// additionally requires witness to be a fresh high-entropy nonce.
func (k *CommitmentKey) CommitWithWitness(message Message, witness Witness) (Commitment, error) {
	if k == nil {
		return Commitment{}, commitments.ErrIsNil.WithMessage("commitment key must not be nil")
	}
	h, err := hmacFunc(k[:])
	if err != nil {
		return Commitment{}, errs.Wrap(err).WithMessage("could not create hash function")
	}
	// length prefixing is not necessary because witness is fixed size so encoded message is unambiguous.
	h.Write(message)
	h.Write(witness[:])
	return Commitment(h.Sum(nil)), nil
}

// Open verifies that (message, witness) is a valid opening of commitment under
// this key by recomputing the commitment and comparing. It returns
// commitments.ErrVerificationFailed on mismatch. Binding ensures a single
// commitment cannot be opened to two distinct messages without finding a hash
// collision.
func (k *CommitmentKey) Open(commitment Commitment, message Message, witness Witness) error {
	if k == nil {
		return commitments.ErrIsNil.WithMessage("commitment key must not be nil")
	}
	if err := internal.GenericOpen(k, commitment, message, witness); err != nil {
		return errs.Wrap(err).WithMessage("could not open commitment")
	}
	return nil
}

// Equal reports whether two commitment keys are identical, treating a nil key as
// equal only to another nil key. Keys are public parameters, so the comparison
// need not be constant time.
func (k *CommitmentKey) Equal(other *CommitmentKey) bool {
	if k == nil || other == nil {
		return k == other
	}
	return *k == *other
}
