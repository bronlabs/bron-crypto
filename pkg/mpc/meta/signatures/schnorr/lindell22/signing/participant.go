package signing

import (
	"encoding/hex"
	"fmt"
	"io"
	"slices"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	mpcschnorr "github.com/bronlabs/bron-crypto/pkg/mpc/meta/signatures/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/mpc/meta/signatures/schnorr/lindell22"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/network"
	schnorrpok "github.com/bronlabs/bron-crypto/pkg/proofs/dlog/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike"
)

const (
	transcriptLabel = "BRON_CRYPTO_TSCHNORR_LINDELL22_SIGNING-"
)

// Cosigner is a participant in the Lindell22 threshold Schnorr signing protocol.
type Cosigner[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S], M schnorrlike.Message] struct {
	ctx     *session.Context
	shard   *lindell22.Shard[GE, S]
	group   algebra.PrimeGroup[GE, S]
	sf      algebra.PrimeField[S]
	prng    io.Reader
	round   network.Round
	variant mpcschnorr.MPCFriendlyVariant[GE, S, M]

	niDlogScheme compiler.NonInteractiveProtocol[*schnorrpok.Statement[GE, S], *schnorrpok.Witness[S]]
	state        *State[GE, S]
}

// State holds the cosigner's internal state during the signing protocol.
type State[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S]] struct {
	quorumBytes              [][]byte
	k                        S
	bigR                     GE
	opening                  lindell22.Opening
	theirBigRCommitments     map[sharing.ID]lindell22.Commitment
	ctxFrozenBeforeDlogProof *session.Context
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
	return hashset.NewComparable(slices.Collect(c.ctx.AllPartiesOrdered())...).Freeze()
}

// Shard returns the party's secret key share.
func (c *Cosigner[GE, S, M]) Shard() *lindell22.Shard[GE, S] {
	return c.shard
}

// Variant returns the Schnorr variant being used for signing.
func (c *Cosigner[GE, S, M]) Variant() mpcschnorr.MPCFriendlyVariant[GE, S, M] {
	return c.variant
}

// NewCosigner creates a new cosigner for threshold Schnorr signing.
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

	return &Cosigner[GE, S, M]{
		ctx:          ctx,
		shard:        shard,
		group:        group,
		sf:           sf,
		prng:         prng,
		niDlogScheme: niDlogScheme,
		variant:      variant,
		round:        1,
		state: &State[GE, S]{
			quorumBytes:              quorumBytes,
			k:                        *new(S),
			bigR:                     *new(GE),
			opening:                  lindell22.Opening{},
			theirBigRCommitments:     make(map[sharing.ID]lindell22.Commitment, ctx.Quorum().Size()-1),
			ctxFrozenBeforeDlogProof: nil,
		},
	}, nil
}
