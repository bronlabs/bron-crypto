package hjky

import (
	"encoding/hex"
	"fmt"
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/feldman"
	"github.com/bronlabs/bron-crypto/pkg/network"
)

const (
	transcriptLabel  = "BRON_CRYPTO_HJKY-"
	coefficientLabel = "BRON_CRYPTO_HJKY_COEFFICIENT-"
)

// Participant executes the HJKY zero-sharing protocol.
type Participant[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	ctx    *session.Context
	group  algebra.PrimeGroup[G, S]
	field  algebra.PrimeField[S]
	scheme *feldman.Scheme[G, S]
	round  network.Round
	prng   io.Reader
	state  State[G, S]
}

// State stores participant-local protocol state across HJKY rounds.
type State[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	verificationVectors map[sharing.ID]*feldman.VerificationVector[G, S]
	share               *feldman.Share[S]
}

// NewParticipant creates a zero-sharing participant bound to the given session and access structure.
func NewParticipant[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](ctx *session.Context, as accessstructures.Monotone, g algebra.PrimeGroup[G, S], prng io.Reader) (*Participant[G, S], error) {
	if ctx == nil || prng == nil || as == nil {
		return nil, ErrInvalidArgument.WithMessage("invalid arguments")
	}
	if !ctx.Quorum().Equal(as.Shareholders()) {
		return nil, ErrInvalidArgument.WithMessage("access structure doesn't match context")
	}

	field := algebra.StructureMustBeAs[algebra.PrimeField[S]](g.ScalarStructure())
	vssScheme, err := feldman.NewScheme(g, as)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create feldman scheme")
	}
	sid := ctx.SessionID()
	ctx.Transcript().AppendDomainSeparator(fmt.Sprintf("%s%s", transcriptLabel, hex.EncodeToString(sid[:])))

	return &Participant[G, S]{
		ctx:    ctx,
		group:  g,
		field:  field,
		scheme: vssScheme,
		round:  1,
		prng:   prng,
		state: State[G, S]{
			verificationVectors: nil,
			share:               nil,
		},
	}, nil
}

// SharingID returns the identifier for this participant within the access structure.
func (p *Participant[G, S]) SharingID() sharing.ID {
	return p.ctx.HolderID()
}

// Context returns the session context associated with this participant.
func (p *Participant[G, S]) Context() *session.Context {
	return p.ctx
}
