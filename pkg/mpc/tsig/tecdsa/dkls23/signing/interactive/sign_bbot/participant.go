package sign_bbot

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	rvole_bbot "github.com/bronlabs/bron-crypto/pkg/mpc/rvole/bbot"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tecdsa"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
	"github.com/bronlabs/errs-go/errs"
)

const (
	transcriptLabel = "BRON_CRYPTO_TECDSA_DKLS23_BBOT-"
	mulLabel        = "BRON_CRYPTO_TECDSA_DKLS23_BBOT_MUL-"
	ckLabel         = "BRON_CRYPTO_TECDSA_DKLS23_BBOT_CK-"
)

// Cosigner represents a signing participant.
type Cosigner[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	ctx   *session.Context
	suite *ecdsa.Suite[P, B, S]
	shard *tecdsa.Shard[P, B, S]
	prng  io.Reader
	state CosignerState[P, B, S]
}

// CosignerState tracks per-round signing state.
type CosignerState[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	aliceMul map[sharing.ID]*rvole_bbot.Alice[P, S]
	bobMul   map[sharing.ID]*rvole_bbot.Bob[P, S]

	round          network.Round
	ck             *hash_comm.Scheme
	r              S
	bigR           map[sharing.ID]P
	bigRCommitment map[sharing.ID]hash_comm.Commitment
	bigRWitness    hash_comm.Witness
	phi            S
	chi            map[sharing.ID]S
	c              map[sharing.ID][]S
	sk             S
	pk             map[sharing.ID]P
}

// NewCosigner returns a new cosigner.
func NewCosigner[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](ctx *session.Context, suite *ecdsa.Suite[P, B, S], shard *tecdsa.Shard[P, B, S], prng io.Reader) (*Cosigner[P, B, S], error) {
	if ctx == nil || suite == nil || shard == nil || prng == nil {
		return nil, ErrNil.WithMessage("argument")
	}
	if suite.IsDeterministic() {
		return nil, ErrValidation.WithMessage("suite must be non-deterministic")
	}
	if ctx.HolderID() != shard.Share().ID() {
		return nil, ErrValidation.WithMessage("sharing id not part of the quorum")
	}
	if !shard.AccessStructure().IsQualified(ctx.Quorum().List()...) {
		return nil, ErrValidation.WithMessage("unqualified quorum")
	}

	sid := ctx.SessionID()
	ctx.Transcript().AppendDomainSeparator(fmt.Sprintf("%s%s", transcriptLabel, hex.EncodeToString(sid[:])))

	//nolint:exhaustruct // lazy initialisation
	c := &Cosigner[P, B, S]{
		ctx:   ctx,
		shard: shard,
		suite: suite,
		prng:  prng,
	}

	mulSuite, err := rvole_bbot.NewSuite(2, suite.Curve())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create mul suite")
	}
	c.state.aliceMul = make(map[sharing.ID]*rvole_bbot.Alice[P, S])
	c.state.bobMul = make(map[sharing.ID]*rvole_bbot.Bob[P, S])
	for id := range c.ctx.OtherPartiesOrdered() {
		aliceTape := ctx.Transcript().Clone()
		aliceTape.AppendBytes(mulLabel, binary.LittleEndian.AppendUint64(nil, uint64(c.ctx.HolderID())), binary.LittleEndian.AppendUint64(nil, uint64(id)))
		c.state.aliceMul[id], err = rvole_bbot.NewAlice(c.ctx.SessionID(), mulSuite, prng, aliceTape)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("couldn't initialise alice")
		}

		bobTape := ctx.Transcript().Clone()
		bobTape.AppendBytes(mulLabel, binary.LittleEndian.AppendUint64(nil, uint64(id)), binary.LittleEndian.AppendUint64(nil, uint64(c.ctx.HolderID())))
		c.state.bobMul[id], err = rvole_bbot.NewBob(c.ctx.SessionID(), mulSuite, prng, bobTape)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("couldn't initialise bob")
		}
	}

	c.state.round = 1
	return c, nil
}

// SharingID returns the participant sharing identifier.
func (c *Cosigner[P, B, S]) SharingID() sharing.ID {
	return c.ctx.HolderID()
}

// Quorum returns the protocol quorum.
func (c *Cosigner[P, B, S]) Quorum() network.Quorum {
	return c.ctx.Quorum()
}
