package aor

import (
	"iter"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/network"
)

func validateIncomingBroadcastMessages[MB network.Message](p *Participant, rIn network.Round, uIn network.RoundMessages[MB]) (iter.Seq2[sharing.ID, MB], error) {
	if rIn != p.round {
		return nil, ErrRound.WithMessage("invalid round")
	}

	incomingParties := uIn.Keys()
	for id := range p.quorum.Iter() {
		if id == p.id {
			continue
		}
		if !slices.Contains(incomingParties, id) {
			return nil, ErrFailed.WithMessage("missing broadcast message from %d", id)
		}
	}

	return func(yield func(p sharing.ID, m MB) bool) {
		for id := range p.quorum.Iter() {
			if id == p.id {
				continue
			}

			u, ok := uIn.Get(id)
			if !ok {
				panic("this should never happen: missing broadcast message")
			}
			if !yield(id, u) {
				return
			}
		}
	}, nil
}
