package dkg

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tecdsa"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/vsot"
	"github.com/bronlabs/bron-crypto/pkg/ot/extension/softspoken"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
	"github.com/bronlabs/errs-go/errs"
)

const (
	transcriptLabel = "BRON_CRYPTO_DKLS23_DKG-"
	vsotLabel       = "BRON_CRYPTO_DKLS23_DKG_VSOT-"
)

// Participant represents a DKG participant.
type Participant[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	ctx       *session.Context
	baseShard *tecdsa.Shard[P, B, S]
	prng      io.Reader
	round     network.Round

	baseOTSenders   map[sharing.ID]*vsot.Sender[P, B, S]
	baseOTReceivers map[sharing.ID]*vsot.Receiver[P, B, S]
	state           state[P, B, S]
}

type state[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	senderSeeds   ds.MutableMap[sharing.ID, *vsot.SenderOutput]
	receiverSeeds ds.MutableMap[sharing.ID, *vsot.ReceiverOutput]
}

// NewParticipant returns a new participant.
func NewParticipant[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](ctx *session.Context, baseShard *tecdsa.Shard[P, B, S], prng io.Reader) (*Participant[P, B, S], error) {
	if baseShard == nil || prng == nil || ctx == nil {
		return nil, ErrNil.WithMessage("argument")
	}
	if !ctx.Quorum().Equal(baseShard.BaseShard.AccessStructure().Shareholders()) {
		return nil, ErrFailed.WithMessage("quorum does not match base shard")
	}
	sid := ctx.SessionID()
	ctx.Transcript().AppendDomainSeparator(fmt.Sprintf("%s%s", transcriptLabel, hex.EncodeToString(sid[:])))

	curve := algebra.StructureMustBeAs[ecdsa.Curve[P, B, S]](baseShard.PublicKey().Value().Structure())
	otSuite, err := vsot.NewSuite(softspoken.Kappa, 1, curve, sha256.New)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("error creating vsot suite for participant")
	}
	otSenders := make(map[sharing.ID]*vsot.Sender[P, B, S])
	otReceivers := make(map[sharing.ID]*vsot.Receiver[P, B, S])
	for id := range ctx.OtherPartiesOrdered() {
		otCtx, err := ctx.SubContext(hashset.NewComparable(ctx.HolderID(), id).Freeze())
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("error creating subcontext")
		}
		otCtx.Transcript().AppendBytes(vsotLabel, binary.LittleEndian.AppendUint64(nil, uint64(ctx.HolderID())), binary.LittleEndian.AppendUint64(nil, uint64(id)))
		otSender, err := vsot.NewSender(otCtx, otSuite, prng)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("error creating vsot sender")
		}

		otCtx, err = ctx.SubContext(hashset.NewComparable(ctx.HolderID(), id).Freeze())
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("error creating subcontext")
		}
		otCtx.Transcript().AppendBytes(vsotLabel, binary.LittleEndian.AppendUint64(nil, uint64(id)), binary.LittleEndian.AppendUint64(nil, uint64(ctx.HolderID())))
		otReceiver, err := vsot.NewReceiver(otCtx, otSuite, prng)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("error creating vsot receiver")
		}

		otSenders[id] = otSender
		otReceivers[id] = otReceiver
	}

	//nolint:exhaustruct // lazy initialisation
	p := &Participant[P, B, S]{
		ctx:             ctx,
		baseShard:       baseShard,
		prng:            prng,
		round:           1,
		baseOTSenders:   otSenders,
		baseOTReceivers: otReceivers,
	}
	return p, nil
}

// SharingID returns the participant sharing identifier.
func (p *Participant[P, B, S]) SharingID() sharing.ID {
	return p.ctx.HolderID()
}
