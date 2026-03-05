package refresh

import (
	"encoding/hex"
	"fmt"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig"
	"github.com/bronlabs/bron-crypto/pkg/mpc/zero/hjky"
	"github.com/bronlabs/errs-go/errs"
)

const (
	transcriptLabel = "BRON_CRYPTO_REFRESH-"
)

// Participant orchestrates share refresh using a zero-sum offset.
type Participant[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	shard           *tsig.BaseShard[G, S]
	zeroParticipant *hjky.Participant[G, S]
}

// NewParticipant constructs a shard refresher using the HjKy zero-sharing subprotocol.
func NewParticipant[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](ctx *session.Context, shard *tsig.BaseShard[G, S], prng io.Reader) (*Participant[G, S], error) {
	if shard == nil || ctx == nil || prng == nil {
		return nil, ErrInvalidArgument.WithMessage("argument is nil")
	}

	sid := ctx.SessionID()
	ctx.Transcript().AppendDomainSeparator(fmt.Sprintf("%s%s", transcriptLabel, hex.EncodeToString(sid[:])))
	group := algebra.StructureMustBeAs[algebra.PrimeGroup[G, S]](shard.VerificationVector().Coefficients()[0].Structure())
	zeroParticipant, err := hjky.NewParticipant(ctx, shard.AccessStructure(), group, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create zero participant")
	}

	p := &Participant[G, S]{
		shard:           shard,
		zeroParticipant: zeroParticipant,
	}

	return p, nil
}

// SharingID returns the identifier of the refreshed shard.
func (p *Participant[G, S]) SharingID() sharing.ID {
	return p.shard.Share().ID()
}
