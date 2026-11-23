package iknp03

import (
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/ot"
)

// validateSession checks that ctx is a two-party session and returns the
// counterparty's identifier; the session guarantees its holder is in the
// quorum, so a quorum of two leaves exactly one other party.
func validateSession(ctx *session.Context) (sharing.ID, error) {
	if ctx == nil {
		return 0, ot.ErrInvalidArgument.WithMessage("session context must not be nil")
	}
	if size := ctx.Quorum().Size(); size != 2 {
		return 0, ot.ErrInvalidArgument.WithMessage("quorum has %d parties, expected 2", size)
	}
	return slices.Collect(ctx.OtherPartiesOrdered())[0], nil
}

// validateBaseCount checks that the base OTs number exactly κ, the width of
// the output rows and of Δ, which the output message type M fixes.
func validateBaseCount[M ot.Message](count int) error {
	if kappa := ot.MessageBitLen[M](); count != kappa {
		return ot.ErrInvalidArgument.WithMessage("%d base OTs, expected %d for %d-bit rows", count, kappa, kappa)
	}
	return nil
}
