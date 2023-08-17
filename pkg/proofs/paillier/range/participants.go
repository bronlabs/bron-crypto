package paillierrange

import (
	"io"
	"math/big"

	"github.com/copperexchange/knox-primitives/pkg/commitments"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
	"github.com/copperexchange/knox-primitives/pkg/paillier"
	"github.com/copperexchange/knox-primitives/pkg/transcripts"
	"github.com/copperexchange/knox-primitives/pkg/transcripts/hagrid"
)

const (
	transcriptAppLabel       = "PAILLIER_RANGE_PROOF"
	transcriptSessionIdLabel = "PaillierRange_SessionId"
)

type Participant struct {
	t     int // security parameter (i.e. a cheating prover can succeed with probability less then 2^(-t))
	q     *big.Int
	l     *big.Int
	round int
	sid   []byte
	prng  io.Reader

	_ helper_types.Incomparable
}

type ProverState struct {
	esidCommitment commitments.Commitment
	w1             []*big.Int
	r1             []*big.Int
	w2             []*big.Int
	r2             []*big.Int

	_ helper_types.Incomparable
}

type Prover struct {
	Participant
	x     *big.Int
	r     *big.Int
	sk    *paillier.SecretKey
	state *ProverState

	_ helper_types.Incomparable
}

type VerifierState struct {
	e           *big.Int
	esidWitness commitments.Witness
	c1          []paillier.CipherText
	c2          []paillier.CipherText

	_ helper_types.Incomparable
}

type Verifier struct {
	Participant
	c     paillier.CipherText
	pk    *paillier.PublicKey
	state *VerifierState

	_ helper_types.Incomparable
}

func NewProver(t int, q *big.Int, sid []byte, sk *paillier.SecretKey, x, r *big.Int, sessionId []byte, transcript transcripts.Transcript, prng io.Reader) (prover *Prover, err error) {
	if len(sessionId) == 0 {
		return nil, errs.NewInvalidArgument("invalid session id: %s", sessionId)
	}
	if transcript == nil {
		transcript = hagrid.NewTranscript(transcriptAppLabel)
	}
	transcript.AppendMessages(transcriptSessionIdLabel, sessionId)

	// 2.i. computes l = ceil(q/3)
	l := new(big.Int).Div(new(big.Int).Add(q, big.NewInt(2)), big.NewInt(3)) // l = ceil(q/3)

	// 2.ii. computes c = c (-) l
	xMinusQThird := new(big.Int).Sub(x, l)

	return &Prover{
		Participant: Participant{
			t:     t,
			q:     q,
			l:     l,
			round: 2,
			sid:   sid,
			prng:  prng,
		},
		x:     xMinusQThird,
		r:     r,
		sk:    sk,
		state: &ProverState{},
	}, nil
}

func NewVerifier(t int, q *big.Int, sid []byte, pk *paillier.PublicKey, xEncrypted paillier.CipherText, sessionId []byte, transcript transcripts.Transcript, prng io.Reader) (verifier *Verifier, err error) {
	if len(sessionId) == 0 {
		return nil, errs.NewInvalidArgument("invalid session id: %s", sessionId)
	}
	if transcript == nil {
		transcript = hagrid.NewTranscript(transcriptAppLabel)
	}
	transcript.AppendMessages(transcriptSessionIdLabel, sessionId)

	// 1.i. computes l = ceil(q/3)
	l := new(big.Int).Div(new(big.Int).Add(q, big.NewInt(2)), big.NewInt(3)) // l = ceil(q/3)

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
