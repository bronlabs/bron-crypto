package lpdl

import (
	"fmt"
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/encryptions/paillier"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/paillier/lp"
	paillierrange "github.com/copperexchange/krypton-primitives/pkg/proofs/paillier/range"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
	hashcommitments "github.com/copperexchange/krypton-primitives/pkg/vector_commitments/hash"
)

const (
	transcriptLabel = "COPPER_KRYPTON_PAILLIER_LPDL-"
)

type Participant struct {
	pk         *paillier.PublicKey
	bigQ       curves.Point
	round      int
	sessionId  []byte
	transcript transcripts.Transcript
	prng       io.Reader

	_ ds.Incomparable
}

type State struct {
	curve curves.Curve
	q     *saferith.Modulus
	q2    *saferith.Modulus
	a     *saferith.Nat
	b     *saferith.Nat

	_ ds.Incomparable
}

type VerifierState struct {
	State
	cDoublePrimeOpening hashcommitments.Opening
	bigQPrime           curves.Point
	cHat                hashcommitments.Commitment

	_ ds.Incomparable
}

type Verifier struct {
	Participant
	rangeVerifier *paillierrange.Verifier
	c             *paillier.CipherText
	state         *VerifierState

	_ ds.Incomparable
}

type ProverState struct {
	State
	alpha                  *saferith.Nat
	bigQHat                curves.Point
	bigQHatOpening         hashcommitments.Opening
	cDoublePrimeCommitment hashcommitments.Commitment

	_ ds.Incomparable
}

type Prover struct {
	Participant
	rangeProver *paillierrange.Prover
	sk          *paillier.SecretKey
	x           curves.Scalar
	state       *ProverState

	_ ds.Incomparable
}

func NewVerifier(publicKey *paillier.PublicKey, bigQ curves.Point, xEncrypted *paillier.CipherText, sessionId []byte, transcript transcripts.Transcript, prng io.Reader) (verifier *Verifier, err error) {
	err = validateVerifierInputs(publicKey, bigQ, xEncrypted, sessionId, prng)
	if err != nil {
		return nil, errs.WrapArgument(err, "invalid input arguments")
	}

	curve := bigQ.Curve()
	dst := fmt.Sprintf("%s-%s", transcriptLabel, curve.Name())
	if transcript == nil {
		transcript = hagrid.NewTranscript(dst, prng)
	}
	boundSessionId, err := transcript.Bind(sessionId, dst)
	if err != nil {
		return nil, errs.WrapHashing(err, "couldn't initialise transcript/sessionId")
	}

	q := curve.Order()
	q2 := saferith.ModulusFromNat(new(saferith.Nat).Mul(q.Nat(), q.Nat(), 2*q.BitLen()))

	rangeProofTranscript := transcript.Clone()
	rangeVerifier, err := paillierrange.NewVerifier(base.ComputationalSecurity, q.Nat(),
		publicKey, xEncrypted, sessionId, rangeProofTranscript, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create Paillier range verifier")
	}

	return &Verifier{
		Participant: Participant{
			pk:         publicKey,
			bigQ:       bigQ,
			round:      1,
			sessionId:  boundSessionId,
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

func validateVerifierInputs(publicKey *paillier.PublicKey, bigQ curves.Point, xEncrypted *paillier.CipherText, sessionId []byte, prng io.Reader) error {
	if len(sessionId) == 0 {
		return errs.NewIsNil("sessionId is nil")
	}
	if publicKey == nil {
		return errs.NewIsNil("public key is nil")
	}
	if publicKey.N.TrueLen() < lp.PaillierBitSize {
		return errs.NewArgument("invalid paillier public key: modulus is too small")
	}
	if bigQ == nil {
		return errs.NewIsNil("bigQ is nil")
	}
	if xEncrypted == nil {
		return errs.NewIsNil("xEncrypted is nil")
	}
	if xEncrypted.C.EqZero() != 0 {
		return errs.NewArgument("xEncrypted is zero")
	}
	if prng == nil {
		return errs.NewIsNil("prng is nil")
	}
	return nil
}

func NewProver(secretKey *paillier.SecretKey, x curves.Scalar, r *saferith.Nat, sessionId []byte, transcript transcripts.Transcript, prng io.Reader) (verifier *Prover, err error) {
	err = validateProverInputs(secretKey, x, r, sessionId, prng)
	if err != nil {
		return nil, errs.WrapArgument(err, "invalid input arguments")
	}

	curve := x.ScalarField().Curve()
	dst := fmt.Sprintf("%s-%s", transcriptLabel, curve.Name())
	if transcript == nil {
		transcript = hagrid.NewTranscript(dst, prng)
	}
	boundSessionId, err := transcript.Bind(sessionId, dst)
	if err != nil {
		return nil, errs.WrapHashing(err, "couldn't initialise participant transcript/sessionId")
	}

	q := curve.Order()
	qSquared := saferith.ModulusFromNat(new(saferith.Nat).Mul(q.Nat(), q.Nat(), -1))

	rangeProofTranscript := transcript.Clone()
	rangeProver, _ := paillierrange.NewProver(base.ComputationalSecurity, q.Nat(),
		secretKey, x.Nat(), r, sessionId, rangeProofTranscript, prng)

	return &Prover{
		Participant: Participant{
			pk:         &secretKey.PublicKey,
			bigQ:       curve.ScalarBaseMult(x),
			round:      2,
			sessionId:  boundSessionId,
			transcript: transcript,
			prng:       prng,
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

func validateProverInputs(secretKey *paillier.SecretKey, x curves.Scalar, r *saferith.Nat, sessionId []byte, prng io.Reader) error {
	if len(sessionId) == 0 {
		return errs.NewIsNil("sessionId is nil")
	}
	if secretKey == nil {
		return errs.NewIsNil("secret key is nil")
	}
	if secretKey.N.TrueLen() < lp.PaillierBitSize {
		return errs.NewSize("invalid paillier public key: modulus is too small")
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
