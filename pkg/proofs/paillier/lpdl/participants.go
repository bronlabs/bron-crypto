package lpdl

import (
	"io"
	"math/big"

	"github.com/copperexchange/knox-primitives/pkg/commitments"
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
	"github.com/copperexchange/knox-primitives/pkg/paillier"
	paillierrange "github.com/copperexchange/knox-primitives/pkg/proofs/paillier/range"
	"github.com/copperexchange/knox-primitives/pkg/transcripts"
	"github.com/copperexchange/knox-primitives/pkg/transcripts/hagrid"
)

const (
	transcriptAppLabel       = "PAILLIER_LPDL_PROOF"
	transcriptSessionIdLabel = "PaillierLP_SessionId"
)

type Participant struct {
	pk         *paillier.PublicKey
	bigQ       curves.Point
	round      int
	sessionId  []byte
	transcript transcripts.Transcript
	prng       io.Reader

	_ helper_types.Incomparable
}

type State struct {
	curve curves.Curve
	q     *big.Int
	q2    *big.Int
	a     *big.Int
	b     *big.Int

	_ helper_types.Incomparable
}

type VerifierState struct {
	State
	cDoublePrimeWitness commitments.Witness
	bigQPrime           curves.Point
	cHat                commitments.Commitment

	_ helper_types.Incomparable
}

type Verifier struct {
	Participant
	rangeVerifier *paillierrange.Verifier
	c             paillier.CipherText
	state         *VerifierState

	_ helper_types.Incomparable
}

type ProverState struct {
	State
	alpha                  *big.Int
	bigQHat                curves.Point
	bigQHatWitness         commitments.Witness
	cDoublePrimeCommitment commitments.Commitment

	_ helper_types.Incomparable
}

type Prover struct {
	Participant
	rangeProver *paillierrange.Prover
	sk          *paillier.SecretKey
	x           curves.Scalar
	state       *ProverState

	_ helper_types.Incomparable
}

func NewVerifier(sid []byte, publicKey *paillier.PublicKey, bigQ curves.Point, xEncrypted paillier.CipherText, sessionId []byte, transcript transcripts.Transcript, prng io.Reader) (verifier *Verifier, err error) {
	if len(sessionId) == 0 {
		return nil, errs.NewInvalidArgument("invalid session id: %s", sessionId)
	}
	if transcript == nil {
		transcript = hagrid.NewTranscript(transcriptAppLabel)
	}
	transcript.AppendMessages(transcriptSessionIdLabel, sessionId)

	curve, err := bigQ.Curve()
	if err != nil {
		return nil, errs.WrapInvalidCurve(err, "invalid curve %s", curve.Name())
	}
	q := curve.Profile().SubGroupOrder()
	q2 := new(big.Int).Mul(q, q)

	rangeProofTranscript := transcript.Clone()
	rangeVerifier, err := paillierrange.NewVerifier(128, q, sid, publicKey, xEncrypted, sessionId, rangeProofTranscript, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create Paillier range verifier")
	}

	return &Verifier{
		Participant: Participant{
			pk:         publicKey,
			bigQ:       bigQ,
			round:      1,
			sessionId:  sessionId,
			transcript: transcript,
			prng:       prng,
		},
		rangeVerifier: rangeVerifier,
		c:             xEncrypted,
		state: &VerifierState{
			State: State{
				curve: curve,
				q:     q,
				q2:    q2,
			},
		},
	}, nil
}

func NewProver(sid []byte, secretKey *paillier.SecretKey, x curves.Scalar, r *big.Int, sessionId []byte, transcript transcripts.Transcript, prng io.Reader) (verifier *Prover, err error) {
	if len(sessionId) == 0 {
		return nil, errs.NewInvalidArgument("invalid session id: %s", sessionId)
	}
	if transcript == nil {
		transcript = hagrid.NewTranscript(transcriptAppLabel)
	}
	transcript.AppendMessages(transcriptSessionIdLabel, sessionId)

	curve, err := x.Curve()
	if err != nil {
		return nil, errs.WrapInvalidCurve(err, "invalid curve %s", curve.Name())
	}
	q := curve.Profile().SubGroupOrder()
	q2 := new(big.Int).Mul(q, q)

	rangeProofTranscript := transcript.Clone()
	rangeProver, err := paillierrange.NewProver(128, q, sid, secretKey, x.BigInt(), r, sessionId, rangeProofTranscript, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create Paillier range prover")
	}

	return &Prover{
		Participant: Participant{
			pk:    &secretKey.PublicKey,
			bigQ:  curve.ScalarBaseMult(x),
			round: 2,
		},
		rangeProver: rangeProver,
		sk:          secretKey,
		x:           x,
		state: &ProverState{
			State: State{
				curve: curve,
				q:     q,
				q2:    q2,
			},
		},
	}, nil
}
