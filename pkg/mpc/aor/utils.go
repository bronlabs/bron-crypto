package aor

import (
	"iter"
	"slices"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/network"
)

func validateIncomingBroadcastMessages[MB network.Message[*Participant]](p *Participant, rIn network.Round, uIn network.RoundMessages[MB, *Participant]) (iter.Seq2[sharing.ID, MB], error) {
	if rIn != p.round {
		return nil, ErrRound.WithMessage("invalid round")
	}

	incomingParties := uIn.Keys()
	validated := make([]struct {
		id sharing.ID
		m  MB
	}, 0, len(incomingParties))
	for id := range p.quorum.Iter() {
		if id == p.id {
			continue
		}
		if !slices.Contains(incomingParties, id) {
			return nil, ErrFailed.WithMessage("missing broadcast message from %d", id)
		}
		u, ok := uIn.Get(id)
		if !ok {
			return nil, ErrFailed.WithMessage("missing broadcast message from %d", id)
		}
		if err := u.Validate(p, id); err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("failed to validate broadcast message from %d", id)
		}
		validated = append(validated, struct {
			id sharing.ID
			m  MB
		}{id: id, m: u})
	}

	return func(yield func(p sharing.ID, m MB) bool) {
		for _, v := range validated {
			if !yield(v.id, v.m) {
				return
			}
		}
	}, nil
}
