package dkg

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/vsot"
	"github.com/bronlabs/bron-crypto/pkg/ot/extension/softspoken"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
	"github.com/bronlabs/bron-crypto/pkg/threshold/dkg/gennaro"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/przs"
	przsSetup "github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/przs/setup"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

const (
	transcriptLabel = "BRON_CRYPTO_DKLS23_DKG-"
	vsotLabel       = "BRON_CRYPTO_DKLS23_DKG_VSOT-"
)

type Participant[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	sessionId network.SID
	baseShard *tecdsa.Shard[P, B, S]
	tape      transcripts.Transcript
	prng      io.Reader
	round     network.Round

	zeroSetup       *przsSetup.Participant
	baseOTSenders   map[sharing.ID]*vsot.Sender[P, B, S]
	baseOTReceivers map[sharing.ID]*vsot.Receiver[P, B, S]
	state           state[P, B, S]
}

type state[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	senderSeeds   ds.MutableMap[sharing.ID, *vsot.SenderOutput]
	receiverSeeds ds.MutableMap[sharing.ID, *vsot.ReceiverOutput]
	dkgOutput     *gennaro.DKGOutput[P, S]
	zeroSeeds     przs.Seeds
}

func NewParticipant[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](sessionId network.SID, sharingId sharing.ID, baseShard *tecdsa.Shard[P, B, S], tape transcripts.Transcript, prng io.Reader) (*Participant[P, B, S], error) {
	if baseShard == nil || tape == nil || prng == nil {
		return nil, errs.NewIsNil("argument")
	}
	tape.AppendDomainSeparator(fmt.Sprintf("%s%s", transcriptLabel, sessionId))

	zeroSetup, err := przsSetup.NewParticipant(sessionId, sharingId, baseShard.AccessStructure().Shareholders(), tape, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "error creating zero setup for participant")
	}

	curve := algebra.StructureMustBeAs[ecdsa.Curve[P, B, S]](baseShard.PublicKey().Value().Structure())
	otSuite, err := vsot.NewSuite(softspoken.Kappa, 1, curve, sha256.New)
	if err != nil {
		return nil, errs.WrapFailed(err, "error creating vsot suite for participant")
	}
	otSenders := make(map[sharing.ID]*vsot.Sender[P, B, S])
	otReceivers := make(map[sharing.ID]*vsot.Receiver[P, B, S])
	for id := range baseShard.AccessStructure().Shareholders().Iter() {
		if id == sharingId {
			continue
		}

		otTape := tape.Clone()
		otTape.AppendBytes(vsotLabel, binary.LittleEndian.AppendUint64(nil, uint64(sharingId)), binary.LittleEndian.AppendUint64(nil, uint64(id)))
		otSender, err := vsot.NewSender(sessionId, otSuite, otTape, prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "error creating vsot sender")
		}

		otTape = tape.Clone()
		otTape.AppendBytes(vsotLabel, binary.LittleEndian.AppendUint64(nil, uint64(id)), binary.LittleEndian.AppendUint64(nil, uint64(sharingId)))
		otReceiver, err := vsot.NewReceiver(sessionId, otSuite, otTape, prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "error creating vsot receiver")
		}

		otSenders[id] = otSender
		otReceivers[id] = otReceiver
	}

	p := &Participant[P, B, S]{
		sessionId:       sessionId,
		baseShard:       baseShard,
		tape:            tape,
		prng:            prng,
		round:           1,
		zeroSetup:       zeroSetup,
		baseOTSenders:   otSenders,
		baseOTReceivers: otReceivers,
	}
	return p, nil
}

func (p *Participant[P, B, S]) SharingID() sharing.ID {
	return p.baseShard.Share().ID()
}
