package vsot

import (
	"hash"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

type participant[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	sessionId network.SID
	chi       int
	curve     curves.Curve[P, B, S]
	field     algebra.PrimeField[S]
	hashFunc  func() hash.Hash
	tape      transcripts.Transcript
	prng      io.Reader
}

func (p *participant[P, B, S]) hash(b, a P, data []byte) ([]byte, error) {
	digest, err := hashing.HashPrefixedLength(p.hashFunc, p.sessionId[:], b.ToCompressed(), a.ToCompressed(), data)
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

func NewSender[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]](sessionId network.SID, chi int, curve curves.Curve[P, B, S], hashFunc func() hash.Hash, tape transcripts.Transcript, prng io.Reader) (*Sender[P, B, S], error) {
	if hashFunc == nil || tape == nil || prng == nil {
		return nil, errs.NewValidation("invalid args")
	}
	if chi <= 0 || (chi%8) != 0 {
		return nil, errs.NewValidation("invalid chi")
	}

	field, ok := curve.ScalarStructure().(algebra.PrimeField[S])
	if !ok {
		return nil, errs.NewFailed("invalid curve scalar structure")
	}
	s := &Sender[P, B, S]{
		participant: participant[P, B, S]{
			sessionId: sessionId,
			chi:       chi,
			curve:     curve,
			hashFunc:  hashFunc,
			field:     field,
			tape:      tape,
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

func NewReceiver[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]](sessionId network.SID, chi int, curve curves.Curve[P, B, S], hashFunc func() hash.Hash, tape transcripts.Transcript, prng io.Reader) (*Receiver[P, B, S], error) {
	if hashFunc == nil || tape == nil || prng == nil {
		return nil, errs.NewValidation("invalid args")
	}
	if chi < 0 || (chi%8) != 0 {
		return nil, errs.NewValidation("invalid chi")
	}

	field, ok := curve.ScalarStructure().(algebra.PrimeField[S])
	if !ok {
		return nil, errs.NewFailed("invalid curve scalar structure")
	}
	r := &Receiver[P, B, S]{
		participant: participant[P, B, S]{
			sessionId: sessionId,
			chi:       chi,
			curve:     curve,
			field:     field,
			hashFunc:  hashFunc,
			tape:      tape,
			prng:      prng,
		},
	}

	return r, nil
}
