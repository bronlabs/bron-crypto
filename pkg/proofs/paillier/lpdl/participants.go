package lpdl

import (
	"fmt"
	"io"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	hashcommitments "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/proofs/paillier/lp"
	paillierrange "github.com/bronlabs/bron-crypto/pkg/proofs/paillier/range"
	zkcompiler "github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/zk"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
)

const (
	transcriptLabel = "BRON_CRYPTO_PAILLIER_LPDL-"
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
	cDoublePrimeWitness hashcommitments.Witness
	bigQPrime           curves.Point
	cHat                hashcommitments.Commitment

	_ ds.Incomparable
}

type Verifier struct {
	Participant
	rangeVerifier *zkcompiler.Verifier[*paillierrange.Statement, *paillierrange.Witness, *paillierrange.Commitment, *paillierrange.State, *paillierrange.Response]
	c             *paillier.CipherText
	state         *VerifierState

	_ ds.Incomparable
}

type ProverState struct {
	State
	alpha                  *saferith.Int
	bigQHat                curves.Point
	bigQHatWitness         hashcommitments.Witness
	cDoublePrimeCommitment hashcommitments.Commitment

	_ ds.Incomparable
}

type Prover struct {
	Participant
	rangeProver *zkcompiler.Prover[*paillierrange.Statement, *paillierrange.Witness, *paillierrange.Commitment, *paillierrange.State, *paillierrange.Response]
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
	qThird := new(saferith.Nat).Div(q.Nat(), saferith.ModulusFromUint64(3), q.BitLen())

	rangeProofTranscript := transcript.Clone()
	rangeProtocol, err := paillierrange.NewPaillierRange(base.ComputationalSecurity, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't create range protocol")
	}
	rangeCipherText, err := publicKey.CipherTextSubPlainText(xEncrypted, new(saferith.Int).SetNat(qThird))
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't create range statement")
	}
	rangeStatement := paillierrange.NewStatement(publicKey, rangeCipherText, qThird)
	rangeVerifier, err := zkcompiler.NewVerifier(boundSessionId, rangeProofTranscript, rangeProtocol, rangeStatement, prng)
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
	if publicKey.N.BitLen() < lp.PaillierBitSize {
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
	qThird := new(saferith.Nat).Div(q.Nat(), saferith.ModulusFromUint64(3), q.BitLen())

	rangeProofTranscript := transcript.Clone()

	rangeProtocol, err := paillierrange.NewPaillierRange(base.ComputationalSecurity, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't create range protocol")
	}
	rangePlainText, err := secretKey.PlainTextSub(new(saferith.Int).SetNat(x.Nat()), new(saferith.Int).SetNat(qThird))
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't create range witness")
	}
	rangeCipherText, err := secretKey.EncryptWithNonce(rangePlainText, r)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't create range statement")
	}
	rangeWitness := paillierrange.NewWitness(secretKey, rangePlainText, r)
	rangeStatement := paillierrange.NewStatement(&secretKey.PublicKey, rangeCipherText, qThird)
	rangeProver, err := zkcompiler.NewProver(boundSessionId, rangeProofTranscript, rangeProtocol, rangeStatement, rangeWitness)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't initialise prover")
	}

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
	if secretKey.N.BitLen() < lp.PaillierBitSize {
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
