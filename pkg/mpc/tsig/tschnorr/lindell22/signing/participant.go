package signing

import (
	"encoding/hex"
	"fmt"
	"io"
	"slices"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/unanimity"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tschnorr"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tschnorr/lindell22"
	"github.com/bronlabs/bron-crypto/pkg/mpc/zero/przs"
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
	variant tschnorr.MPCFriendlyVariant[GE, S, M]

	niDlogScheme compiler.NonInteractiveProtocol[*schnorrpok.Statement[GE, S], *schnorrpok.Witness[S], *schnorrpok.State[S]]
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
func (c *Cosigner[GE, S, M]) Variant() tschnorr.MPCFriendlyVariant[GE, S, M] {
	return c.variant
}

// ComputePartialSignature computes this party's contribution to the threshold signature.
func (c *Cosigner[GE, S, M]) ComputePartialSignature(aggregatedNonceCommitment GE, challenge S) (*lindell22.PartialSignature[GE, S], error) {
	if c == nil {
		return nil, ErrNilArgument.WithMessage("cosigner cannot be nil")
	}
	if c.round != 3 {
		return nil, ErrInvalidRound.WithMessage("cosigner %d cannot compute partial signature in round %d, expected round 3", c.ctx.HolderID(), c.round)
	}

	// step 3.7.1: compute additive share d_i'
	quorum, err := unanimity.NewUnanimityAccessStructure(c.Quorum())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create minimal qualified access structure for quorum %v", c.Quorum())
	}
	zero, err := przs.SampleZeroShare(c.ctx, c.sf)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot sample zero share")
	}
	ashare, err := c.shard.Share().ToAdditive(quorum)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot convert share %d to additive share", c.shard.Share().ID())
	}
	ashare = ashare.Add(zero)

	myAdditiveShare, err := c.variant.CorrectAdditiveSecretShareParity(c.shard.PublicKey(), ashare)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot correct share %d parity", c.shard.Share().ID())
	}
	// step 3.7.3 & 3.8: compute s'_i and set s_i <- s'_i + ζ_i
	correctedR, correctedK, err := c.variant.CorrectPartialNonceParity(aggregatedNonceCommitment, c.state.k)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot correct nonce parity")
	}
	s, err := c.variant.ComputeResponse(myAdditiveShare.Value(), correctedK, challenge)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot compute response")
	}
	return &lindell22.PartialSignature[GE, S]{
		Sig: schnorrlike.Signature[GE, S]{
			E: challenge,
			R: correctedR,
			S: s,
		},
	}, nil
}

// NewCosigner creates a new cosigner for threshold Schnorr signing.
func NewCosigner[
	GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S], M schnorrlike.Message,
](
	ctx *session.Context,
	shard *lindell22.Shard[GE, S],
	niCompilerName compiler.Name,
	variant tschnorr.MPCFriendlyVariant[GE, S, M],
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
	if !shard.AccessStructure().IsQualified(ctx.Quorum().List()...) {
		return nil, ErrInvalidMembership.WithMessage("shard %d access structure is not authorized for quorum %s", shard.Share().ID(), ctx.Quorum())
	}
	if prng == nil {
		return nil, ErrNilArgument.WithMessage("prng cannot be nil")
	}

	schnorrProtocol, err := schnorrpok.NewProtocol(group.Generator())
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
