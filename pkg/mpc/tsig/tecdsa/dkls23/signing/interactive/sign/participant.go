package sign

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	rvole_softspoken "github.com/bronlabs/bron-crypto/pkg/mpc/rvole/softspoken"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tecdsa"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/ecbbot"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/vsot"
	"github.com/bronlabs/bron-crypto/pkg/ot/extension/softspoken"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

const (
	baseOtMessageLength = 32

	transcriptLabel      = "BRON_CRYPTO_TECDSA_DKLS23_ECBBOT_SOFTSPOKEN-"
	mulLabel             = "BRON_CRYPTO_TECDSA_DKLS23_ECBBOT_SOFTSPOKEN_MUL-"
	ckLabel              = "BRON_CRYPTO_TECDSA_DKLS23_ECBBOT_SOFTSPOKEN_CK-"
	otRandomizerLabel    = "BRON_CRYPTO_TECDSA_DKLS23_ECBBOT_SOFTSPOKEN_OT_RANDOMIZER-"
	otRandomizerSender   = "BRON_CRYPTO_TECDSA_DKLS23_ECBBOT_SOFTSPOKEN_OT_RANDOMIZER_SENDER-"
	otRandomizerReceiver = "BRON_CRYPTO_TECDSA_DKLS23_ECBBOT_SOFTSPOKEN_OT_RANDOMIZER_RECEIVER-"
	otRandomizerKey      = "BRON_CRYPTO_TECDSA_DKLS23_ECBBOT_SOFTSPOKEN_OT_RANDOMIZER_KEY-"
	ecbbotLabel          = "BRON_CRYPTO_TECDSA_DKLS23_ECBBOT_SOFTSPOKEN_BASE_OT-"
)

// Cosigner represents a signing participant.
type Cosigner[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	ctx   *session.Context
	shard *tecdsa.Shard[P, B, S]
	suite *ecdsa.Suite[P, B, S]
	prng  io.Reader

	baseOtSenders   map[sharing.ID]*ecbbot.Sender[P, S]
	baseOtReceivers map[sharing.ID]*ecbbot.Receiver[P, S]
	aliceMul        map[sharing.ID]*rvole_softspoken.Alice[P, B, S]
	bobMul          map[sharing.ID]*rvole_softspoken.Bob[P, B, S]

	state State[P, B, S]
}

// State tracks per-round signing state.
type State[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	baseOtReceiverOutputs map[sharing.ID]*vsot.ReceiverOutput
	baseOtSenderOutputs   map[sharing.ID]*vsot.SenderOutput

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
		return nil, ErrValidation.WithMessage("inconsistent share id")
	}
	if !ctx.Quorum().Contains(shard.Share().ID()) {
		return nil, ErrValidation.WithMessage("sharing id not part of the quorum")
	}
	if !shard.AccessStructure().IsQualified(ctx.Quorum().List()...) {
		return nil, ErrValidation.WithMessage("unqualified quorum")
	}

	sid := ctx.SessionID()
	ctx.Transcript().AppendDomainSeparator(fmt.Sprintf("%s%s", transcriptLabel, hex.EncodeToString(sid[:])))

	otSuite, err := ecbbot.NewSuite(softspoken.Kappa, 1, suite.Curve())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("error creating vsot suite for participant")
	}
	otSenders := make(map[sharing.ID]*ecbbot.Sender[P, S])
	otReceivers := make(map[sharing.ID]*ecbbot.Receiver[P, S])
	sharingID := shard.Share().ID()
	for id := range ctx.OtherPartiesOrdered() {
		otCtx, err := ctx.SubContext(hashset.NewComparable(ctx.HolderID(), id).Freeze())
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("error creating subcontext")
		}
		otCtx.Transcript().AppendBytes(ecbbotLabel, binary.LittleEndian.AppendUint64(nil, uint64(sharingID)), binary.LittleEndian.AppendUint64(nil, uint64(id)))
		otSender, err := ecbbot.NewSender(otCtx, otSuite, prng)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("error creating bbot sender")
		}

		otCtx, err = ctx.SubContext(hashset.NewComparable(ctx.HolderID(), id).Freeze())
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("error creating subcontext")
		}
		otCtx.Transcript().AppendBytes(ecbbotLabel, binary.LittleEndian.AppendUint64(nil, uint64(id)), binary.LittleEndian.AppendUint64(nil, uint64(sharingID)))
		otReceiver, err := ecbbot.NewReceiver(otCtx, otSuite, prng)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("error creating bbot receiver")
		}

		otSenders[id] = otSender
		otReceivers[id] = otReceiver
	}

	//nolint:exhaustruct // lazy initialisation
	c := &Cosigner[P, B, S]{
		ctx:             ctx,
		shard:           shard,
		suite:           suite,
		prng:            prng,
		baseOtSenders:   otSenders,
		baseOtReceivers: otReceivers,
		aliceMul:        make(map[sharing.ID]*rvole_softspoken.Alice[P, B, S]),
		bobMul:          make(map[sharing.ID]*rvole_softspoken.Bob[P, B, S]),
		//nolint:exhaustruct // lazy initialisation
		state: State[P, B, S]{
			baseOtReceiverOutputs: make(map[sharing.ID]*vsot.ReceiverOutput),
			baseOtSenderOutputs:   make(map[sharing.ID]*vsot.SenderOutput),
			round:                 1,
		},
	}
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
