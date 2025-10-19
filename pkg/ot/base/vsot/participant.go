package vsot

import (
	"encoding/hex"
	"fmt"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

const (
	transcriptLabel = "BRON_CRYPTO_VSOT-"
	aLabel          = "BRON_CRYPTO_VSOT-A-"
)

type participant[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	sessionId network.SID
	suite     *Suite[P, B, S]
	tape      transcripts.Transcript
	round     int
	prng      io.Reader
}

func (p *participant[P, B, S]) hash(b, a P, data []byte) ([]byte, error) {
	digest, err := hashing.HashPrefixedLength(p.suite.HashFunc(), p.sessionId[:], b.ToCompressed(), a.ToCompressed(), data)
	if err != nil {
		return nil, errs.WrapHashing(err, "cannot compute hash")
	}
	return digest, nil
}

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

func NewSender[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]](sessionId network.SID, suite *Suite[P, B, S], tape transcripts.Transcript, prng io.Reader) (*Sender[P, B, S], error) {
	if suite == nil || tape == nil || prng == nil {
		return nil, errs.NewValidation("invalid args")
	}

	tape.AppendDomainSeparator(fmt.Sprintf("%s-%s", transcriptLabel, hex.EncodeToString(sessionId[:])))
	s := &Sender[P, B, S]{
		participant: participant[P, B, S]{
			sessionId: sessionId,
			suite:     suite,
			tape:      tape,
			round:     1,
			prng:      prng,
		},
	}

	return s, nil
}

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

func NewReceiver[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]](sessionId network.SID, suite *Suite[P, B, S], tape transcripts.Transcript, prng io.Reader) (*Receiver[P, B, S], error) {
	if suite == nil || tape == nil || prng == nil {
		return nil, errs.NewValidation("invalid args")
	}

	tape.AppendDomainSeparator(fmt.Sprintf("%s-%s", transcriptLabel, hex.EncodeToString(sessionId[:])))
	r := &Receiver[P, B, S]{
		participant: participant[P, B, S]{
			sessionId: sessionId,
			suite:     suite,
			tape:      tape,
			round:     2,
			prng:      prng,
		},
	}

	return r, nil
}
