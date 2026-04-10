package signing

import (
	"encoding/hex"
	"fmt"
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/mpc/meta/hjky"
	mpcschnorr "github.com/bronlabs/bron-crypto/pkg/mpc/meta/signatures/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/mpc/meta/signatures/schnorr/lindell22"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/unanimity"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/additive"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/meta/feldman"
	"github.com/bronlabs/bron-crypto/pkg/network"
	schnorrpok "github.com/bronlabs/bron-crypto/pkg/proofs/dlog/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike"
)

const (
	transcriptLabel = "BRON_CRYPTO_TSCHNORR_LINDELL22_SIGNING-"
)

// Cosigner is a participant in the Lindell22 Schnorr signing protocol.
type Cosigner[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S], M schnorrlike.Message] struct {
	ctx     *session.Context
	shard   *lindell22.Shard[GE, S]
	group   algebra.PrimeGroup[GE, S]
	sf      algebra.PrimeField[S]
	prng    io.Reader
	round   network.Round
	variant mpcschnorr.MPCFriendlyVariant[GE, S, M]

	zeroParticipant *hjky.Participant[GE, S]
	niDlogScheme    compiler.NonInteractiveProtocol[*schnorrpok.Statement[GE, S], *schnorrpok.Witness[S]]
	lsss            *feldman.Scheme[GE, S]
	state           *State[GE, S]
}

// State holds the cosigner's internal state during the signing protocol.
type State[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S]] struct {
	quorumBytes              [][]byte
	k                        S
	bigR                     GE
	opening                  lindell22.Opening
	correctedBigRs           map[sharing.ID]GE
	theirBigRCommitments     map[sharing.ID]lindell22.Commitment
	ctxFrozenBeforeDlogProof *session.Context
	zeroAc                   *unanimity.Unanimity
	zeroShift                *additive.Share[S]
	partialPublicKeys        map[sharing.ID]GE
}

// SessionID returns the session identifier for this signing session.
func (c *Cosigner[GE, S, M]) SessionID() network.SID {
	return c.ctx.SessionID()
}

// SharingID returns the party's identifier in the secret sharing scheme.
func (c *Cosigner[GE, S, M]) SharingID() sharing.ID {
	return c.ctx.HolderID()
}

// Quorum returns the set of parties participating in this signing session.
func (c *Cosigner[GE, S, M]) Quorum() network.Quorum {
	return c.ctx.Quorum()
}

// Shard returns the party's secret key share.
func (c *Cosigner[GE, S, M]) Shard() *lindell22.Shard[GE, S] {
	return c.shard
}

// Variant returns the Schnorr variant being used for signing.
func (c *Cosigner[GE, S, M]) Variant() mpcschnorr.MPCFriendlyVariant[GE, S, M] {
	return c.variant
}

// NewCosigner creates a new cosigner for Schnorr signing.
func NewCosigner[
	GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S], M schnorrlike.Message,
](
	ctx *session.Context,
	shard *lindell22.Shard[GE, S],
	niCompilerName compiler.Name,
	variant mpcschnorr.MPCFriendlyVariant[GE, S, M],
	prng io.Reader,
) (*Cosigner[GE, S, M], error) {
	if shard == nil {
		return nil, ErrNilArgument.WithMessage("shard cannot be nil")
	}
	if ctx == nil {
		return nil, ErrNilArgument.WithMessage("context cannot be nil")
	}
	group := shard.PublicKey().Group()
	sf, ok := group.ScalarStructure().(algebra.PrimeField[S])
	if !ok {
		return nil, ErrInvalidType.WithMessage("group %s structure is not a prime field", group.Name())
	}
	if ctx.HolderID() != shard.Share().ID() {
		return nil, ErrInvalidMembership.WithMessage("invalid context")
	}
	if !ctx.Quorum().Contains(shard.Share().ID()) {
		return nil, ErrInvalidMembership.WithMessage("quorum doesn't cannot contain participant %d", shard.Share().ID())
	}
	if !shard.MSP().Accepts(ctx.Quorum().List()...) {
		return nil, ErrInvalidMembership.WithMessage("shard %d access structure is not authorized for quorum %s", shard.Share().ID(), ctx.Quorum())
	}
	if prng == nil {
		return nil, ErrNilArgument.WithMessage("prng cannot be nil")
	}

	schnorrProtocol, err := schnorrpok.NewProtocol(group.Generator(), prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create schnorr protocol")
	}
	niDlogScheme, err := compiler.Compile(niCompilerName, schnorrProtocol, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to compile niDlogProver")
	}

	sid := ctx.SessionID()
	dst := fmt.Sprintf("%s-%s-%s", transcriptLabel, hex.EncodeToString(sid[:]), group.Name())
	ctx.Transcript().AppendDomainSeparator(dst)
	quorumBytes := lindell22.QuorumBytes(ctx.Quorum())

	kwScheme, err := kw.NewInducedScheme(shard.MSP())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create kw scheme")
	}
	feldmanScheme, err := feldman.NewSchemeFromKW(group, kwScheme)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create feldman scheme")
	}

	zeroAc, err := unanimity.NewUnanimityAccessStructure(ctx.Quorum())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create minimal qualified access structure")
	}
	zeroParticipant, err := hjky.NewParticipant(ctx, zeroAc, group, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create zero participant")
	}

	return &Cosigner[GE, S, M]{
		ctx:             ctx,
		shard:           shard,
		group:           group,
		sf:              sf,
		prng:            prng,
		lsss:            feldmanScheme,
		niDlogScheme:    niDlogScheme,
		zeroParticipant: zeroParticipant,
		variant:         variant,
		round:           1,
		state: &State[GE, S]{
			quorumBytes:              quorumBytes,
			k:                        *new(S),
			bigR:                     *new(GE),
			opening:                  lindell22.Opening{},
			theirBigRCommitments:     make(map[sharing.ID]lindell22.Commitment, ctx.Quorum().Size()-1),
			correctedBigRs:           make(map[sharing.ID]GE, ctx.Quorum().Size()),
			ctxFrozenBeforeDlogProof: nil,
			zeroAc:                   zeroAc,
			zeroShift:                nil,
			partialPublicKeys:        nil,
		},
	}, nil
}
