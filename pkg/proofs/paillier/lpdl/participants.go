package lpdl

import (
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"github.com/copperexchange/krypton-primitives/pkg/encryptions/paillier"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/paillier/lp"
	paillierrange "github.com/copperexchange/krypton-primitives/pkg/proofs/paillier/range"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
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

	_ types.Incomparable
}

type State struct {
	curve curves.Curve
	q     *saferith.Modulus
	q2    *saferith.Modulus
	a     *saferith.Nat
	b     *saferith.Nat

	_ types.Incomparable
}

type VerifierState struct {
	State
	cDoublePrimeWitness commitments.Witness
	bigQPrime           curves.Point
	cHat                commitments.Commitment

	_ types.Incomparable
}

type Verifier struct {
	Participant
	rangeVerifier *paillierrange.Verifier
	c             *paillier.CipherText
	state         *VerifierState

	_ types.Incomparable
}

type ProverState struct {
	State
	alpha                  *saferith.Nat
	bigQHat                curves.Point
	bigQHatWitness         commitments.Witness
	cDoublePrimeCommitment commitments.Commitment

	_ types.Incomparable
}

type Prover struct {
	Participant
	rangeProver *paillierrange.Prover
	sk          *paillier.SecretKey
	x           curves.Scalar
	state       *ProverState

	_ types.Incomparable
}

func NewVerifier(sid []byte, publicKey *paillier.PublicKey, bigQ curves.Point, xEncrypted *paillier.CipherText, sessionId []byte, transcript transcripts.Transcript, prng io.Reader) (verifier *Verifier, err error) {
	err = validateVerifierInputs(sid, publicKey, bigQ, xEncrypted, sessionId, prng)
	if err != nil {
		return nil, errs.WrapInvalidArgument(err, "invalid input arguments")
	}

	if transcript == nil {
		transcript = hagrid.NewTranscript(transcriptAppLabel, nil)
	}
	transcript.AppendMessages(transcriptSessionIdLabel, sessionId)

	curve := bigQ.Curve()
	q := curve.Profile().SubGroupOrder()
	q2 := saferith.ModulusFromNat(new(saferith.Nat).Mul(q.Nat(), q.Nat(), 2*q.BitLen()))

	rangeProofTranscript := transcript.Clone()
	rangeVerifier, err := paillierrange.NewVerifier(128, q.Nat(), sid, publicKey, xEncrypted, sessionId, rangeProofTranscript, prng)
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

func validateVerifierInputs(sid []byte, publicKey *paillier.PublicKey, bigQ curves.Point, xEncrypted *paillier.CipherText, sessionId []byte, prng io.Reader) error {
	if len(sessionId) == 0 {
		return errs.NewIsNil("sessionId is nil")
	}
	if len(sid) == 0 {
		return errs.NewIsNil("sid is nil")
	}
	if publicKey == nil {
		return errs.NewIsNil("public key is nil")
	}
	if publicKey.N.BitLen() < lp.PaillierBitSize {
		return errs.NewInvalidArgument("invalid paillier public key: modulus is too small")
	}
	if bigQ == nil {
		return errs.NewIsNil("bigQ is nil")
	}
	if xEncrypted == nil {
		return errs.NewIsNil("xEncrypted is nil")
	}
	if xEncrypted.C.EqZero() != 0 {
		return errs.NewInvalidArgument("xEncrypted is zero")
	}
	if prng == nil {
		return errs.NewIsNil("prng is nil")
	}
	return nil
}

func NewProver(sid []byte, secretKey *paillier.SecretKey, x curves.Scalar, r *saferith.Nat, sessionId []byte, transcript transcripts.Transcript, prng io.Reader) (verifier *Prover, err error) {
	err = validateProverInputs(sid, secretKey, x, r, sessionId, prng)
	if err != nil {
		return nil, errs.WrapInvalidArgument(err, "invalid input arguments")
	}

	if transcript == nil {
		transcript = hagrid.NewTranscript(transcriptAppLabel, nil)
	}
	transcript.AppendMessages(transcriptSessionIdLabel, sessionId)

	curve := x.Curve()
	q := curve.Profile().SubGroupOrder()
	qSquared := saferith.ModulusFromNat(new(saferith.Nat).Mul(q.Nat(), q.Nat(), -1))

	rangeProofTranscript := transcript.Clone()
	rangeProver, _ := paillierrange.NewProver(128, q.Nat(), sid, secretKey, x.Nat(), r, sessionId, rangeProofTranscript, prng)

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
				q2:    qSquared,
			},
		},
	}, nil
}

func validateProverInputs(sid []byte, secretKey *paillier.SecretKey, x curves.Scalar, r *saferith.Nat, sessionId []byte, prng io.Reader) error {
	if len(sessionId) == 0 {
		return errs.NewIsNil("sessionId is nil")
	}
	if len(sid) == 0 {
		return errs.NewIsNil("sid is nil")
	}
	if secretKey == nil {
		return errs.NewIsNil("secret key is nil")
	}
	if secretKey.N.BitLen() < lp.PaillierBitSize {
		return errs.NewInvalidArgument("invalid paillier public key: modulus is too small")
	}
	if x == nil {
		return errs.NewIsNil("x is nil")
	}
	if r == nil {
		return errs.NewIsNil("r is nil")
	}
	if prng == nil {
		return errs.NewIsNil("prng is nil")
	}
	return nil
}
