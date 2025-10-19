package lindell22

import (
	"encoding/binary"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/network"
	schnorrpok "github.com/bronlabs/bron-crypto/pkg/proofs/dlog/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tschnorr"
)

const commitmentDomainRLabel = "Lindell2022SignR-"

type (
	Shard[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S]]            = tschnorr.Shard[GE, S]
	PublicMaterial[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S]]   = tschnorr.PublicMaterial[GE, S]
	PartialSignature[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S]] = tschnorr.PartialSignature[GE, S]
)

// Lindell22 is proven to be secure in standard model only if a UC-secure commitment scheme is used.
// due to CF01, no such scheme can exist without a trusted setup/interaction. So we use a hash-based commitment scheme
// to save some rounds. Implication is having to rely on RO.
type (
	CommitmentScheme = hash_comm.Scheme
	Commitment       = hash_comm.Commitment
	Opening          = hash_comm.Witness
	CommitmentKey    = hash_comm.Key

	// we are hardcoding the usage of the schnorr dlog protocol to lower number of type parameters.
	PokProtocolStatement[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S]] = schnorrpok.Statement[GE, S]
	PokProtocolWitness[S algebra.PrimeFieldElement[S]]                                        = schnorrpok.Witness[S]
)

var NewCommitmentScheme = hash_comm.NewScheme

func NewCommitmentKey(sid network.SID, pid sharing.ID, quorumBytes [][]byte) (CommitmentKey, error) {
	pidBytes := binary.BigEndian.AppendUint64(nil, uint64(pid))
	key, err := hash_comm.NewKeyFromCRSBytes(sid, commitmentDomainRLabel, append([][]byte{pidBytes}, quorumBytes...)...)
	if err != nil {
		return *new(CommitmentKey), errs.WrapFailed(err, "cannot create key for commitment scheme")
	}
	return key, nil
}

// sorted quorum IDs in big-endian format, used for commitment scheme CRS and dlog proofs.
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
