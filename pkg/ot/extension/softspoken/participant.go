package softspoken

import (
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
)

// copartyOf returns the other party of a two-party session, which the IKNP03
// constructor has already validated.
func copartyOf(ctx *session.Context) sharing.ID {
	return slices.Collect(ctx.OtherPartiesOrdered())[0]
}
