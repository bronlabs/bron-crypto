package paillierrange

import (
	"io"
	"math/big"

	"github.com/cronokirby/saferith"

	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	hashcommitments "github.com/bronlabs/krypton-primitives/pkg/commitments/hash"
	"github.com/bronlabs/krypton-primitives/pkg/indcpa/paillier"
	"github.com/bronlabs/krypton-primitives/pkg/transcripts"
	"github.com/bronlabs/krypton-primitives/pkg/transcripts/hagrid"
)

const (
	transcriptLabel = "KRYPTON_RANGE_PROOF-"
)

type Participant struct {
	// Base Participant
	Prng       io.Reader
	Round      int
	SessionId  []byte
	Transcript transcripts.Transcript

	t      int // security parameter (i.e. a cheating prover can succeed with probability less then 2^(-t))
	q      *saferith.Nat
	l      *saferith.Nat
	capLen int

	_ ds.Incomparable
}

func (p *Participant) SoundnessError() int {
	return p.t
}

type ProverState struct {
	eCommitment hashcommitments.Commitment
	w1          []*saferith.Nat
	r1          []*saferith.Nat
	w2          []*saferith.Nat
	r2          []*saferith.Nat

	_ ds.Incomparable
}

type Prover struct {
	Participant
	x     *saferith.Nat
	r     *saferith.Nat
	sk    *paillier.SecretKey
	state *ProverState

	_ ds.Incomparable
}

type VerifierState struct {
	e        *big.Int
	eWitness hashcommitments.Witness
	c1       []*paillier.CipherText
	c2       []*paillier.CipherText

	_ ds.Incomparable
}

type Verifier struct {
	Participant
	c     *paillier.CipherText
	pk    *paillier.PublicKey
	state *VerifierState

	_ ds.Incomparable
}

func NewProver(t int, q *saferith.Nat, sk *paillier.SecretKey, x, r *saferith.Nat, sessionId []byte, transcript transcripts.Transcript, prng io.Reader) (prover *Prover, err error) {
	err = validateProverInputs(q, sk, x, r, sessionId, prng)
	if err != nil {
		return nil, errs.WrapArgument(err, "invalid input arguments")
	}
	if transcript == nil {
		transcript = hagrid.NewTranscript(transcriptLabel, prng)
	}
	boundSessionId, err := transcript.Bind(sessionId, transcriptLabel)
	if err != nil {
		return nil, errs.WrapHashing(err, "couldn't initialise transcript/sessionId")
	}

	capLen := sk.N.AnnouncedLen()

	// 2.i. computes l = ceil(q/3)
	l := new(saferith.Nat).Div(q, saferith.ModulusFromUint64(3), capLen)

	// 2.ii. computes c = c (-) l
	xMinusQThird := new(saferith.Nat).Sub(x, l, capLen)

	return &Prover{
		Participant: Participant{
			Prng:      prng,
			Round:     2,
			SessionId: boundSessionId,
			t:         t,
			q:         q,
			l:         l,
			capLen:    capLen,
		},
		x:     xMinusQThird,
		r:     r,
		sk:    sk,
		state: &ProverState{},
	}, nil
}

func validateProverInputs(q *saferith.Nat, sk *paillier.SecretKey, x, r *saferith.Nat, sessionId []byte, prng io.Reader) error {
	if len(sessionId) == 0 {
		return errs.NewArgument("invalid session id: %s", sessionId)
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

func NewVerifier(t int, q *saferith.Nat, pk *paillier.PublicKey, xEncrypted *paillier.CipherText, sessionId []byte, transcript transcripts.Transcript, prng io.Reader) (verifier *Verifier, err error) {
	err = validateVerifierInputs(q, pk, xEncrypted, sessionId, prng)
	if err != nil {
		return nil, errs.WrapArgument(err, "invalid input arguments")
	}

	if transcript == nil {
		transcript = hagrid.NewTranscript(transcriptLabel, prng)
	}
	sessionId, err = transcript.Bind(sessionId, transcriptLabel)
	if err != nil {
		return nil, errs.WrapHashing(err, "couldn't initialise transcript/sessionId")
	}

	capLen := pk.N.AnnouncedLen()

	// 1.i. computes l = ceil(q/3)
	l := new(saferith.Nat).Div(q, saferith.ModulusFromUint64(3), capLen)

	// 1.ii. computes c = c (-) l
	cMinusQThirdEncrypted, err := pk.CipherTextSubPlainText(xEncrypted, l)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot encrypt l")
	}

	return &Verifier{
		Participant: Participant{
			t:         t,
			q:         q,
			l:         l,
			Round:     1,
			SessionId: sessionId,
			Prng:      prng,
		},
		c:     cMinusQThirdEncrypted,
		pk:    pk,
		state: &VerifierState{},
	}, nil
}

func validateVerifierInputs(q *saferith.Nat, pk *paillier.PublicKey, xEncrypted *paillier.CipherText, sessionId []byte, prng io.Reader) error {
	if len(sessionId) == 0 {
		return errs.NewArgument("invalid session id: %s", sessionId)
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
