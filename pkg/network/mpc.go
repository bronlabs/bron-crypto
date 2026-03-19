package network

import (
	"iter"

	"github.com/bronlabs/errs-go/errs"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
)

// Round is the sequential identifier of a protocol step.
type Round = uint64

// RoundMessages maps sender IDs to their round messages.
type RoundMessages[M Message[P], P any] = ds.Map[sharing.ID, M]

// OutgoingUnicasts maps recipients to outbound unicast payloads.
type OutgoingUnicasts[M Message[P], P any] = ds.Map[sharing.ID, M]

// Quorum is the set of parties participating in a session.
type Quorum = ds.Set[sharing.ID]

func ValidateIncomingMessages[M Message[P], P any](p P, messages RoundMessages[M, P], senders iter.Seq[sharing.ID]) error {
	for id := range senders {
		m, ok := messages.Get(id)
		if !ok {
			return ErrMissing.WithMessage("from %d", id)
		}
		if err := m.Validate(p); err != nil {
			return errs.Wrap(err)
		}
	}

	return nil
}

var (
	ErrMissing = errs.New("missing message")
)
