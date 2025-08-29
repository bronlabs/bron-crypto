package dkg

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"iter"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/vsot"
	"github.com/bronlabs/bron-crypto/pkg/ot/extension/softspoken"
	"github.com/bronlabs/bron-crypto/pkg/threshold/dkg/gennaro"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/shamir"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/przs"
	przsSetup "github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/przs/setup"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

const (
	transcriptLabel = "BRON_CRYPTO_DKLS23_DKG-"
	vsotLabel       = "BRON_CRYPTO_DKLS23_DKG_VSOT-"
)

type Participant[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	sessionId network.SID
	sharingId sharing.ID
	ac        *shamir.AccessStructure
	suite     *Suite[P, B, S]
	tape      transcripts.Transcript
	prng      io.Reader

	gennaroParty    *gennaro.Participant[P, S]
	zeroSetup       *przsSetup.Participant
	baseOTSenders   map[sharing.ID]*vsot.Sender[P, B, S]
	baseOTReceivers map[sharing.ID]*vsot.Receiver[P, B, S]
	state           state[P, B, S]
}

type state[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	senderSeeds   ds.MutableMap[sharing.ID, *vsot.SenderOutput]
	receiverSeeds ds.MutableMap[sharing.ID, *vsot.ReceiverOutput]
	dkgOutput     *gennaro.DKGOutput[P, S]
	zeroSeeds     przs.Seeds
}

func NewParticipant[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]](sessionId network.SID, sharingId sharing.ID, ac *shamir.AccessStructure, suite *Suite[P, B, S], tape transcripts.Transcript, prng io.Reader) (*Participant[P, B, S], error) {
	// TODO: validation
	tape.AppendDomainSeparator(fmt.Sprintf("%s%s", transcriptLabel, sessionId))

	gennaroParty, err := gennaro.NewParticipant(sessionId, suite.curve, sharingId, ac, tape, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to make gennaro participant")
	}

	zeroSetup, err := przsSetup.NewParticipant(sessionId, sharingId, ac.Shareholders(), tape, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "error creating zero setup for participant")
	}

	otSuite, err := vsot.NewSuite(softspoken.Kappa, 1, suite.curve, sha256.New)
	if err != nil {
		return nil, errs.WrapFailed(err, "error creating vsot suite for participant")
	}
	otSenders := make(map[sharing.ID]*vsot.Sender[P, B, S])
	otReceivers := make(map[sharing.ID]*vsot.Receiver[P, B, S])
	for id := range ac.Shareholders().Iter() {
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
		sharingId:       sharingId,
		ac:              ac,
		suite:           suite,
		tape:            tape,
		prng:            prng,
		gennaroParty:    gennaroParty,
		zeroSetup:       zeroSetup,
		baseOTSenders:   otSenders,
		baseOTReceivers: otReceivers,
	}
	return p, nil
}

func (p *Participant[P, B, S]) SharingID() sharing.ID {
	return p.sharingId
}

func (p *Participant[P, B, S]) otherParties() iter.Seq[sharing.ID] {
	return func(yield func(sharing.ID) bool) {
		for id := range p.ac.Shareholders().Iter() {
			if id == p.sharingId {
				continue
			}
			if !yield(id) {
				return
			}
		}
	}
}
