package network

import (
	"iter"
	"slices"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	ts "github.com/bronlabs/bron-crypto/pkg/transcripts"
)

type Round = uint64

type Party interface {
	Node
	ProtocolName() string
	Transcript() ts.Transcript
	SharingID() sharing.ID
	Round() Round
}

type (
	MPCSession     = Session[Party]
	MPCLocalConfig = LocalConfig[Party]
)

func NewMPCSession(id SID, pki PKI[Party], presentParties ds.Set[Party]) (*MPCSession, error) {
	return NewSession(id, pki, presentParties)
}

type RoundMessages[M Message] = ds.Map[sharing.ID, M]
type OutgoingUnicasts[M Message] ds.Map[sharing.ID, M]
type Quorum = ds.Set[sharing.ID]

func NewQuorum(ids ...sharing.ID) Quorum {
	return hashset.NewComparable(ids...).Freeze()
}

func IterSorted[M Message](input RoundMessages[M]) iter.Seq2[sharing.ID, M] {
	return func(yield func(sharing.ID, M) bool) {
		keys := input.Keys()
		slices.Sort(keys)
		for _, k := range keys {
			v, _ := input.Get(k)
			if !yield(k, v) {
				return
			}
		}
	}
}

// func WriteToTape[M Message](
// 	sid SID,
// 	party Party,
// 	input RoundMessages[M],
// ) {
// 	dst := fmt.Sprintf("round-%d-of-%s-in-%s", party.Round(), party.ProtocolName(), sid)
// 	party.Transcript().AppendDomainSeparator(dst)
// 	for id, msg := range IterSorted(input) {
// 		label := fmt.Sprintf("message-from-%d-in-round-%d", id, party.Round())
// 		ts.Append(party.Transcript(), label, msg)

// 	}
// }
