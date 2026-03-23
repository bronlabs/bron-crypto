package vsot

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/ot"
)

const (
	transcriptLabel = "BRON_CRYPTO_VSOT-"
	aLabel          = "BRON_CRYPTO_VSOT-A-"
)

type participant[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	ctx   *session.Context
	suite *Suite[P, B, S]
	round int
	prng  io.Reader
}

func (p *participant[P, B, S]) hash(idx int, b, a P, data []byte) ([]byte, error) {
	sessionID := p.ctx.SessionID()
	digest, err := hashing.HashIndexLengthPrefixed(p.suite.HashFunc(), binary.LittleEndian.AppendUint64(nil, uint64(idx)), sessionID[:], b.ToCompressed(), a.ToCompressed(), data)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot compute hash")
	}
	return digest, nil
}

// Sender drives the VSOT sender state machine.
type Sender[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	participant[P, B, S]

	state senderState[P, B, S]
}

type senderState[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	b                S
	bigB             P
	rho0Digest       [][]byte
	rho1Digest       [][]byte
	rho0DigestDigest [][]byte
}

// NewSender creates a VSOT sender bound to the session, suite, transcript, and randomness source.
func NewSender[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]](ctx *session.Context, suite *Suite[P, B, S], prng io.Reader) (*Sender[P, B, S], error) {
	if suite == nil || ctx == nil || prng == nil {
		return nil, ot.ErrInvalidArgument.WithMessage("invalid args")
	}

	sessionID := ctx.SessionID()
	ctx.Transcript().AppendDomainSeparator(fmt.Sprintf("%s-%s", transcriptLabel, hex.EncodeToString(sessionID[:])))
	s := &Sender[P, B, S]{
		participant: participant[P, B, S]{
			ctx:   ctx,
			suite: suite,
			round: 1,
			prng:  prng,
		},
		state: senderState[P, B, S]{}, //nolint:exhaustruct // zero value, populated during protocol
	}

	return s, nil
}

// Receiver drives the VSOT receiver state machine.
type Receiver[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	participant[P, B, S]

	state receiverState[P, B, S]
}

type receiverState[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	bigB           P
	bigA           []P
	rhoOmega       [][]byte
	rhoOmegaDigest [][]byte
	omegaRaw       []uint64
	omega          []S
	xi             [][]byte
}

// NewReceiver creates a VSOT receiver bound to the session, suite, transcript, and randomness source.
func NewReceiver[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]](ctx *session.Context, suite *Suite[P, B, S], prng io.Reader) (*Receiver[P, B, S], error) {
	if suite == nil || ctx == nil || prng == nil {
		return nil, ot.ErrInvalidArgument.WithMessage("invalid args")
	}

	sessionID := ctx.SessionID()
	ctx.Transcript().AppendDomainSeparator(fmt.Sprintf("%s-%s", transcriptLabel, hex.EncodeToString(sessionID[:])))
	r := &Receiver[P, B, S]{
		participant: participant[P, B, S]{
			ctx:   ctx,
			suite: suite,
			round: 2,
			prng:  prng,
		},
		state: receiverState[P, B, S]{}, //nolint:exhaustruct // zero value, populated during protocol
	}

	return r, nil
}
