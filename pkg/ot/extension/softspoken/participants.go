package softspoken

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"slices"

	"golang.org/x/crypto/blake2b"

	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/ot"
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

// Sender drives the SoftSpoken sender state machine.
type Sender struct {
	participant

	receiverSeeds *vsot.ReceiverOutput
}

// Receiver drives the SoftSpoken receiver state machine.
type Receiver struct {
	participant

	senderSeeds *vsot.SenderOutput
}

// NewSender constructs a SoftSpoken sender with VSOT seed outputs.
func NewSender(sessionId network.SID, receiverSeeds *vsot.ReceiverOutput, suite *Suite, tape transcripts.Transcript, prng io.Reader) (*Sender, error) {
	if receiverSeeds == nil || prng == nil {
		return nil, ot.ErrInvalidArgument.WithMessage("invalid args")
	}
	if receiverSeeds.InferredXi() != Kappa || receiverSeeds.InferredL() != 1 {
		return nil, ot.ErrInvalidArgument.WithMessage("invalid receiver seeds")
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

// NewReceiver constructs a SoftSpoken receiver with VSOT seed outputs.
func NewReceiver(sessionId network.SID, senderSeeds *vsot.SenderOutput, suite *Suite, tape transcripts.Transcript, prng io.Reader) (*Receiver, error) {
	if senderSeeds == nil || prng == nil {
		return nil, ot.ErrInvalidArgument.WithMessage("invalid args")
	}
	if senderSeeds.InferredXi() != Kappa || senderSeeds.InferredL() != 1 {
		return nil, ot.ErrInvalidArgument.WithMessage("invalid sender seeds")
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

func (p *participant) hash(j, l int, data ...[]byte) ([]byte, error) {
	preimage := slices.Concat(p.sessionId[:], binary.LittleEndian.AppendUint64(nil, uint64(j)), binary.LittleEndian.AppendUint64(nil, uint64(l)))
	for _, d := range data {
		preimage = slices.Concat(preimage, d)
	}
	out, err := hashing.Hash(p.suite.hashFunc, preimage)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot hash data")
	}
	return out, nil
}

// expand derives pseudorandom output from a seed message and choice bit.
func (p *participant) expand(outputLen, idx int, message []byte, choice int) ([]byte, error) {
	xof, err := blake2b.NewXOF(blake2b.OutputLengthUnknown, p.sessionId[:])
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot create blake2b XOF")
	}
	_, err = xof.Write(slices.Concat(binary.LittleEndian.AppendUint64(nil, uint64(idx)), binary.LittleEndian.AppendUint64(nil, uint64(choice)), message))
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot write to blake2b XOF")
	}
	digest := make([]byte, outputLen)
	if _, err = io.ReadFull(xof, digest); err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot read digest")
	}
	return digest, nil
}
