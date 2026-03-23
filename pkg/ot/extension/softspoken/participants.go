package softspoken

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"slices"

	"golang.org/x/crypto/blake2b"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/ot"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/vsot"
)

const (
	transcriptLabel         = "BRON_CRYPTO_SOFTSPOKEN_OT-"
	expansionMaskLabel      = "BRON_CRYPTO_SOFTSPOKEN_OT_EXPANSION_MASK-"
	challengeResponseXLabel = "BRON_CRYPTO_SOFTSPOKEN_OT_CHALLENGE_RESPONSE_X-"
	challengeResponseTLabel = "BRON_CRYPTO_SOFTSPOKEN_OT_CHALLENGE_RESPONSE_T-"
)

type participant struct {
	ctx   *session.Context
	suite *Suite
	round int
	prng  io.Reader
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
func NewSender(ctx *session.Context, receiverSeeds *vsot.ReceiverOutput, suite *Suite, prng io.Reader) (*Sender, error) {
	if receiverSeeds == nil || suite == nil || ctx == nil || prng == nil {
		return nil, ot.ErrInvalidArgument.WithMessage("invalid args")
	}
	if receiverSeeds.InferredXi() != Kappa || receiverSeeds.InferredL() != 1 {
		return nil, ot.ErrInvalidArgument.WithMessage("invalid receiver seeds")
	}

	sessionID := ctx.SessionID()
	ctx.Transcript().AppendDomainSeparator(fmt.Sprintf("%s-%s", transcriptLabel, hex.EncodeToString(sessionID[:])))
	s := &Sender{
		participant: participant{
			ctx,
			suite,
			2,
			prng,
		},
		receiverSeeds: receiverSeeds,
	}

	return s, nil
}

// NewReceiver constructs a SoftSpoken receiver with VSOT seed outputs.
func NewReceiver(ctx *session.Context, senderSeeds *vsot.SenderOutput, suite *Suite, prng io.Reader) (*Receiver, error) {
	if senderSeeds == nil || suite == nil || ctx == nil || prng == nil {
		return nil, ot.ErrInvalidArgument.WithMessage("invalid args")
	}
	if senderSeeds.InferredXi() != Kappa || senderSeeds.InferredL() != 1 {
		return nil, ot.ErrInvalidArgument.WithMessage("invalid sender seeds")
	}

	sessionID := ctx.SessionID()
	ctx.Transcript().AppendDomainSeparator(fmt.Sprintf("%s-%s", transcriptLabel, hex.EncodeToString(sessionID[:])))
	r := &Receiver{
		participant: participant{
			ctx,
			suite,
			1,
			prng,
		},
		senderSeeds: senderSeeds,
	}

	return r, nil
}

func (p *participant) hash(j, l int, data ...[]byte) ([]byte, error) {
	sessionID := p.ctx.SessionID()
	preimage := slices.Concat(sessionID[:], binary.LittleEndian.AppendUint64(nil, uint64(j)), binary.LittleEndian.AppendUint64(nil, uint64(l)))
	for _, d := range data {
		preimage = slices.Concat(preimage, d)
	}
	out, err := hashing.Hash(p.suite.hashFunc, preimage)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot hash data")
	}
	return out, nil
}

// expand derives pseudorandom output from a seed message and choice bit.
func (p *participant) expand(outputLen, idx int, message []byte, choice int) ([]byte, error) {
	sessionID := p.ctx.SessionID()
	xof, err := blake2b.NewXOF(blake2b.OutputLengthUnknown, sessionID[:])
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create blake2b XOF")
	}
	_, err = xof.Write(slices.Concat(binary.LittleEndian.AppendUint64(nil, uint64(idx)), binary.LittleEndian.AppendUint64(nil, uint64(choice)), message))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot write to blake2b XOF")
	}
	digest := make([]byte, outputLen)
	if _, err = io.ReadFull(xof, digest); err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot read digest")
	}
	return digest, nil
}
