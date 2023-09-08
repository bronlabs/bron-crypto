package paillierrange

import (
	"io"
	"math/big"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton/pkg/base/errs"
	"github.com/copperexchange/krypton/pkg/base/types"
	"github.com/copperexchange/krypton/pkg/commitments"
	"github.com/copperexchange/krypton/pkg/encryptions/paillier"
	"github.com/copperexchange/krypton/pkg/transcripts"
	"github.com/copperexchange/krypton/pkg/transcripts/hagrid"
)

const (
	transcriptAppLabel       = "PAILLIER_RANGE_PROOF"
	transcriptSessionIdLabel = "PaillierRange_SessionId"
)

type Participant struct {
	t      int // security parameter (i.e. a cheating prover can succeed with probability less then 2^(-t))
	q      *saferith.Nat
	l      *saferith.Nat
	capLen int
	round  int
	sid    []byte
	prng   io.Reader

	_ types.Incomparable
}

type ProverState struct {
	esidCommitment commitments.Commitment
	w1             []*saferith.Nat
	r1             []*saferith.Nat
	w2             []*saferith.Nat
	r2             []*saferith.Nat

	_ types.Incomparable
}

type Prover struct {
	Participant
	x     *saferith.Nat
	r     *saferith.Nat
	sk    *paillier.SecretKey
	state *ProverState

	_ types.Incomparable
}

type VerifierState struct {
	e           *big.Int
	esidWitness commitments.Witness
	c1          []*paillier.CipherText
	c2          []*paillier.CipherText

	_ types.Incomparable
}

type Verifier struct {
	Participant
	c     *paillier.CipherText
	pk    *paillier.PublicKey
	state *VerifierState

	_ types.Incomparable
}

func NewProver(t int, q *saferith.Nat, sid []byte, sk *paillier.SecretKey, x, r *saferith.Nat, sessionId []byte, transcript transcripts.Transcript, prng io.Reader) (prover *Prover, err error) {
	err = validateProverInputs(q, sid, sk, x, r, sessionId, prng)
	if err != nil {
		return nil, errs.WrapInvalidArgument(err, "invalid input arguments")
	}

	if transcript == nil {
		transcript = hagrid.NewTranscript(transcriptAppLabel)
	}
	transcript.AppendMessages(transcriptSessionIdLabel, sessionId)

	capLen := sk.N.BitLen()

	// 2.i. computes l = ceil(q/3)
	l := new(saferith.Nat).Div(q, saferith.ModulusFromUint64(3), capLen)

	// 2.ii. computes c = c (-) l
	xMinusQThird := new(saferith.Nat).Sub(x, l, capLen)

	return &Prover{
		Participant: Participant{
			t:      t,
			q:      q,
			l:      l,
			capLen: capLen,
			round:  2,
			sid:    sid,
			prng:   prng,
		},
		x:     xMinusQThird,
		r:     r,
		sk:    sk,
		state: &ProverState{},
	}, nil
}

func validateProverInputs(q *saferith.Nat, sid []byte, sk *paillier.SecretKey, x, r *saferith.Nat, sessionId []byte, prng io.Reader) error {
	if len(sessionId) == 0 {
		return errs.NewInvalidArgument("invalid session id: %s", sessionId)
	}
	if len(sid) == 0 {
		return errs.NewInvalidArgument("invalid sid: %s", sid)
	}
	if q == nil {
		return errs.NewIsNil("q is nil")
	}
	if x == nil {
		return errs.NewIsNil("x is nil")
	}
	if r == nil {
		return errs.NewIsNil("r is nil")
	}
	if sk == nil {
		return errs.NewIsNil("sk is nil")
	}
	if prng == nil {
		return errs.NewIsNil("prng is nil")
	}
	return nil
}

func NewVerifier(t int, q *saferith.Nat, sid []byte, pk *paillier.PublicKey, xEncrypted *paillier.CipherText, sessionId []byte, transcript transcripts.Transcript, prng io.Reader) (verifier *Verifier, err error) {
	err = validateVerifierInputs(q, sid, pk, xEncrypted, sessionId, prng)
	if err != nil {
		return nil, errs.WrapInvalidArgument(err, "invalid input arguments")
	}

	if transcript == nil {
		transcript = hagrid.NewTranscript(transcriptAppLabel)
	}
	transcript.AppendMessages(transcriptSessionIdLabel, sessionId)

	capLen := pk.N.BitLen()

	// 1.i. computes l = ceil(q/3)
	l := new(saferith.Nat).Div(q, saferith.ModulusFromUint64(3), capLen)

	// 1.ii. computes c = c (-) l
	cMinusQThirdEncrypted, err := pk.SubPlain(xEncrypted, l)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot encrypt l")
	}

	return &Verifier{
		Participant: Participant{
			t:     t,
			q:     q,
			l:     l,
			round: 1,
			sid:   sid,
			prng:  prng,
		},
		c:     cMinusQThirdEncrypted,
		pk:    pk,
		state: &VerifierState{},
	}, nil
}

func validateVerifierInputs(q *saferith.Nat, sid []byte, pk *paillier.PublicKey, xEncrypted *paillier.CipherText, sessionId []byte, prng io.Reader) error {
	if len(sessionId) == 0 {
		return errs.NewInvalidArgument("invalid session id: %s", sessionId)
	}
	if len(sid) == 0 {
		return errs.NewInvalidArgument("invalid sid: %s", sid)
	}
	if q == nil {
		return errs.NewIsNil("q is nil")
	}
	if pk == nil {
		return errs.NewIsNil("pk is nil")
	}
	if xEncrypted == nil {
		return errs.NewIsNil("xEncrypted is nil")
	}
	if prng == nil {
		return errs.NewIsNil("prng is nil")
	}
	return nil
}
