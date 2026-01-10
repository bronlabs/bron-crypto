package lindell22

import (
	"encoding/binary"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tschnorr"
)

const commitmentDomainRLabel = "Lindell2022SignR-"

type (
	// Shard represents a party's secret key share for threshold Schnorr signing.
	Shard[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S]] = tschnorr.Shard[GE, S]
	// PublicMaterial contains public information shared among signing parties.
	PublicMaterial[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S]] = tschnorr.PublicMaterial[GE, S]
	// PartialSignature is a party's contribution to the threshold signature.
	PartialSignature[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S]] = tschnorr.PartialSignature[GE, S]
)

// Lindell22 is proven to be secure in standard model only if a UC-secure commitment scheme is used.
// Due to CF01, no such scheme can exist without a trusted setup/interaction. So we use a hash-based
// commitment scheme to save some rounds. Implication is having to rely on RO.
type (
	// CommitmentScheme is the hash-based commitment scheme used in the protocol.
	CommitmentScheme = hash_comm.Scheme
	// Commitment is a hiding commitment to a value.
	Commitment = hash_comm.Commitment
	// Opening contains the witness needed to open a commitment.
	Opening = hash_comm.Witness
	// CommitmentKey is the public key for the commitment scheme.
	CommitmentKey = hash_comm.Key
)

// NewCommitmentScheme creates a new hash-based commitment scheme.
var NewCommitmentScheme = hash_comm.NewScheme

// NewCommitmentKey creates a commitment key from session ID, party ID, and quorum information.
func NewCommitmentKey(sid network.SID, pid sharing.ID, quorumBytes [][]byte) (CommitmentKey, error) {
	pidBytes := binary.BigEndian.AppendUint64(nil, uint64(pid))
	key, err := hash_comm.NewKeyFromCRSBytes(sid, commitmentDomainRLabel, append([][]byte{pidBytes}, quorumBytes...)...)
	if err != nil {
		return *new(CommitmentKey), errs2.Wrap(err).WithMessage("cannot create key for commitment scheme")
	}
	return key, nil
}

// QuorumBytes returns sorted quorum IDs in big-endian format, used for commitment scheme CRS and dlog proofs.
func QuorumBytes(quorum ds.Set[sharing.ID]) [][]byte {
	if quorum == nil || quorum.Size() == 0 {
		return nil
	}
	bigS := make([][]byte, quorum.Size())
	for i, id := range slices.Sorted(quorum.Iter()) {
		bigS[i] = binary.BigEndian.AppendUint64(nil, uint64(id))
	}
	return bigS
}
