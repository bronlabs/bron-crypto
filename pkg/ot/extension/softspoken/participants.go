package softspoken

import (
	"encoding/hex"
	"fmt"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/vsot"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

const (
	transcriptLabel         = "BRON_CRYPTO_SOFTSPOKEN_OT-"
	expansionMaskLabel      = "BRON_CRYPTO_SOFTSPOKEN_OT_EXPANSION_MASK-"
	challengeResponseXLabel = "BRON_CRYPTO_SOFTSPOKEN_OT_CHALLENGE_RESPONSE_X-"
	challengeResponseTLabel = "BRON_CRYPTO_SOFTSPOKEN_OT_CHALLENGE_RESPONSE_T-"
)

type participant struct {
	sessionId network.SID
	suite     *Suite
	round     int
	tape      transcripts.Transcript
	prng      io.Reader
}

type Sender struct {
	participant

	receiverSeeds *vsot.ReceiverOutput
}

type Receiver struct {
	participant

	senderSeeds *vsot.SenderOutput
}

func NewSender(sessionId network.SID, receiverSeeds *vsot.ReceiverOutput, suite *Suite, tape transcripts.Transcript, prng io.Reader) (*Sender, error) {
	if receiverSeeds == nil || prng == nil {
		return nil, errs.NewValidation("invalid args")
	}
	if receiverSeeds.InferredXi() != Kappa || receiverSeeds.InferredL() != 1 {
		return nil, errs.NewValidation("invalid receiver seeds")
	}

	tape.AppendDomainSeparator(fmt.Sprintf("%s-%s", transcriptLabel, hex.EncodeToString(sessionId[:])))
	s := &Sender{
		participant: participant{
			sessionId,
			suite,
			2,
			tape,
			prng,
		},
		receiverSeeds: receiverSeeds,
	}

	return s, nil
}

func NewReceiver(sessionId network.SID, senderSeeds *vsot.SenderOutput, suite *Suite, tape transcripts.Transcript, prng io.Reader) (*Receiver, error) {
	if senderSeeds == nil || prng == nil {
		return nil, errs.NewValidation("invalid args")
	}
	if senderSeeds.InferredXi() != Kappa || senderSeeds.InferredL() != 1 {
		return nil, errs.NewValidation("invalid sender seeds")
	}

	tape.AppendDomainSeparator(fmt.Sprintf("%s-%s", transcriptLabel, hex.EncodeToString(sessionId[:])))
	r := &Receiver{
		participant: participant{
			sessionId,
			suite,
			1,
			tape,
			prng,
		},
		senderSeeds: senderSeeds,
	}

	return r, nil
}
