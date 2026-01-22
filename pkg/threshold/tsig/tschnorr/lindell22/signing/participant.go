package signing

import (
	"fmt"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/network"
	schnorrpok "github.com/bronlabs/bron-crypto/pkg/proofs/dlog/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tschnorr"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tschnorr/lindell22"
	ts "github.com/bronlabs/bron-crypto/pkg/transcripts"
	"github.com/bronlabs/errs-go/errs"
)

var (
	// ErrNilArgument is returned when a required argument is nil.
	ErrNilArgument = errs.New("nil argument")
	// ErrInvalidRound is returned when an operation is attempted in the wrong round.
	ErrInvalidRound = errs.New("invalid round")
	// ErrInvalidType is returned when a type assertion or check fails.
	ErrInvalidType = errs.New("invalid type")
	// ErrInvalidMembership is returned when a party is not authorized for an operation.
	ErrInvalidMembership = errs.New("invalid membership")
)

const (
	transcriptLabel = "BRON_CRYPTO_TSCHNORR_LINDELL22_SIGNING-"
)

// Cosigner is a participant in the Lindell22 threshold Schnorr signing protocol.
type Cosigner[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S], M schnorrlike.Message] struct {
	sid     network.SID
	shard   *lindell22.Shard[GE, S]
	quorum  network.Quorum
	tape    ts.Transcript
	group   algebra.PrimeGroup[GE, S]
	sf      algebra.PrimeField[S]
	prng    io.Reader
	round   network.Round
	variant tschnorr.MPCFriendlyVariant[GE, S, M]

	niDlogScheme compiler.NonInteractiveProtocol[*schnorrpok.Statement[GE, S], *schnorrpok.Witness[S]]
	state        *State[GE, S]
}

// State holds the cosigner's internal state during the signing protocol.
type State[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S]] struct {
	quorumBytes               [][]byte
	k                         S
	bigR                      GE
	opening                   lindell22.Opening
	theirBigRCommitments      map[sharing.ID]lindell22.Commitment
	tapeFrozenBeforeDlogProof ts.Transcript
}

// SessionID returns the session identifier for this signing session.
func (c *Cosigner[GE, S, M]) SessionID() network.SID {
	if c == nil {
		return network.SID([32]byte{})
	}
	return c.sid
}

// SharingID returns the party's identifier in the secret sharing scheme.
func (c *Cosigner[GE, S, M]) SharingID() sharing.ID {
	if c == nil {
		return 0
	}
	return c.shard.Share().ID()
}

// Quorum returns the set of parties participating in this signing session.
func (c *Cosigner[GE, S, M]) Quorum() network.Quorum {
	if c == nil {
		return nil
	}
	return c.quorum
}

// Shard returns the party's secret key share.
func (c *Cosigner[GE, S, M]) Shard() *lindell22.Shard[GE, S] {
	if c == nil {
		return nil
	}
	return c.shard
}

// Variant returns the Schnorr variant being used for signing.
func (c *Cosigner[GE, S, M]) Variant() tschnorr.MPCFriendlyVariant[GE, S, M] {
	if c == nil {
		return nil
	}
	return c.variant
}

// ComputePartialSignature computes this party's contribution to the threshold signature.
func (c *Cosigner[GE, S, M]) ComputePartialSignature(aggregatedNonceCommitment GE, challenge S) (*lindell22.PartialSignature[GE, S], error) {
	if c == nil {
		return nil, ErrNilArgument.WithMessage("cosigner cannot be nil")
	}
	if c.round != 3 {
		return nil, ErrInvalidRound.WithMessage("cosigner %d cannot compute partial signature in round %d, expected round 3", c.sid, c.round)
	}
	// step 3.7.1: compute additive share d_i'
	mqac, err := sharing.NewMinimalQualifiedAccessStructure(c.quorum)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create minimal qualified access structure for quorum %v", c.quorum)
	}
	ashare, err := c.shard.Share().ToAdditive(mqac)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot convert share %d to additive share", c.shard.Share().ID())
	}
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
	sid network.SID,
	shard *lindell22.Shard[GE, S],
	quorum network.Quorum,
	group algebra.PrimeGroup[GE, S],
	niCompilerName compiler.Name,
	variant tschnorr.MPCFriendlyVariant[GE, S, M],
	prng io.Reader,
	tape ts.Transcript,
) (*Cosigner[GE, S, M], error) {
	if shard == nil {
		return nil, ErrNilArgument.WithMessage("shard cannot be nil")
	}
	if tape == nil {
		return nil, ErrNilArgument.WithMessage("transcript cannot be nil")
	}
	if group == nil {
		return nil, ErrNilArgument.WithMessage("group cannot be nil")
	}
	sf, ok := group.ScalarStructure().(algebra.PrimeField[S])
	if !ok {
		return nil, ErrInvalidType.WithMessage("group %s structure is not a prime field", group.Name())
	}
	if quorum == nil {
		return nil, ErrNilArgument.WithMessage("quorum cannot be nil")
	}
	if !quorum.Contains(shard.Share().ID()) {
		return nil, ErrInvalidMembership.WithMessage("quorum %s cannot contain participant %d", quorum, sid)
	}
	if !shard.AccessStructure().IsAuthorized(quorum.List()...) {
		return nil, ErrInvalidMembership.WithMessage("shard %d access structure is not authorized for quorum %s", shard.Share().ID(), quorum)
	}
	if prng == nil {
		return nil, ErrNilArgument.WithMessage("prng cannot be nil")
	}
	if !group.Order().IsProbablyPrime() {
		return nil, ErrInvalidType.WithMessage("group %s order is not prime", group.Name())
	}
	schnorrProtocol, err := schnorrpok.NewProtocol(group.Generator(), prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create schnorr protocol")
	}
	niDlogScheme, err := compiler.Compile(niCompilerName, schnorrProtocol, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to compile niDlogProver")
	}

	dst := fmt.Sprintf("%s-%d-%s", transcriptLabel, sid, group.Name())
	tape.AppendDomainSeparator(dst)
	quorumBytes := lindell22.QuorumBytes(quorum)

	return &Cosigner[GE, S, M]{
		sid:          sid,
		shard:        shard,
		quorum:       quorum,
		tape:         tape,
		group:        group,
		sf:           sf,
		prng:         prng,
		niDlogScheme: niDlogScheme,
		variant:      variant,
		round:        1,
		state: &State[GE, S]{
			quorumBytes:               quorumBytes,
			k:                         *new(S),
			bigR:                      *new(GE),
			opening:                   lindell22.Opening{},
			theirBigRCommitments:      make(map[sharing.ID]lindell22.Commitment, quorum.Size()-1),
			tapeFrozenBeforeDlogProof: nil,
		},
	}, nil
}
