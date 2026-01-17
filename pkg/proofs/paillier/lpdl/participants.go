package lpdl

import (
	"fmt"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/network"
	paillierrange "github.com/bronlabs/bron-crypto/pkg/proofs/paillier/range"
	zkcompiler "github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/zk"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
)

const (
	appTranscriptLabel       = "BRON_CRYPTO_PAILLIER_LPDL-"
	sessionIdTranscriptLabel = "BRON_CRYPTO_PAILLIER_LPDL_SESSION_ID"
)

// Participant holds common state for the LPDL protocol participants.
type Participant[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	pk         *paillier.PublicKey
	bigQ       P
	round      int
	sessionId  network.SID
	transcript transcripts.Transcript
	prng       io.Reader
}

// State holds shared state for LPDL rounds.
type State[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	curve  curves.Curve[P, B, S]
	zModQ  *num.ZMod
	zModQ2 *num.ZMod
	a      *num.Uint
	b      *num.Uint
}

// VerifierState tracks the verifier's internal state across rounds.
type VerifierState[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	State[P, B, S]

	cDoublePrimeWitness hash_comm.Witness
	bigQPrime           P
	cHat                hash_comm.Commitment
}

// Verifier runs the LPDL verifier role.
type Verifier[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	Participant[P, B, S]

	rangeVerifier     *zkcompiler.Verifier[*paillierrange.Statement, *paillierrange.Witness, *paillierrange.Commitment, *paillierrange.State, *paillierrange.Response]
	paillierEncrypter *paillier.Encrypter
	c                 *paillier.Ciphertext
	state             *VerifierState[P, B, S]
	commitmentScheme  *hash_comm.Scheme
}

// ProverState tracks the prover's internal state across rounds.
type ProverState[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	State[P, B, S]

	alpha                  *paillier.Plaintext
	bigQHat                P
	bigQHatWitness         hash_comm.Witness
	cDoublePrimeCommitment hash_comm.Commitment
}

// Prover runs the LPDL prover role.
type Prover[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	Participant[P, B, S]

	rangeProver       *zkcompiler.Prover[*paillierrange.Statement, *paillierrange.Witness, *paillierrange.Commitment, *paillierrange.State, *paillierrange.Response]
	paillierDecrypter *paillier.Decrypter
	sk                *paillier.PrivateKey
	x                 S
	state             *ProverState[P, B, S]
	commitmentScheme  *hash_comm.Scheme
}

// NewVerifier constructs a verifier instance for the LPDL protocol.
func NewVerifier[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](sessionId network.SID, publicKey *paillier.PublicKey, bigQ P, xEncrypted *paillier.Ciphertext, tape transcripts.Transcript, prng io.Reader) (verifier *Verifier[P, B, S], err error) {
	err = validateVerifierInputs(publicKey, bigQ, xEncrypted, prng)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("invalid input arguments")
	}

	curve := algebra.StructureMustBeAs[curves.Curve[P, B, S]](bigQ.Structure())

	if tape == nil {
		tape = hagrid.NewTranscript(appTranscriptLabel)
	}
	dst := fmt.Sprintf("%s-%d", sessionIdTranscriptLabel, sessionId)
	tape.AppendDomainSeparator(dst)

	rangeProofTranscript := tape.Clone()
	rangeProtocol, q, q2, qThirdNat, err := initRangeProtocol(curve, prng)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("couldn't initialise range protocol")
	}

	// Create Phi(q/3) for homomorphic division
	var qThirdInt numct.Int
	qThirdInt.SetNat(qThirdNat)
	qThirdUnit, err := publicKey.Group().Representative(&qThirdInt)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot compute Phi(q/3)")
	}
	qThird := paillier.NewCiphertextFromUnit(qThirdUnit)

	// xEncrypted has known order, qThird has unknown order from Phi
	// Need to forget order on xEncrypted for the division
	xUnknown := paillier.NewCiphertextFromUnit(xEncrypted.Value().ForgetOrder())
	rangeCiphertext := xUnknown.HomSub(qThird)
	rangeStatement := paillierrange.NewStatement(publicKey, rangeCiphertext, qThirdNat)
	rangeVerifier, err := zkcompiler.NewVerifier(sessionId, rangeProofTranscript, rangeProtocol, rangeStatement, prng)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot create Paillier range verifier")
	}

	ck, err := hash_comm.NewKeyFromCRSBytes(sessionId, appTranscriptLabel)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot instantiate committer")
	}
	commitmentScheme, err := hash_comm.NewScheme(ck)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot instantiate commitment scheme")
	}

	paillierEncrypter, err := paillier.NewScheme().Encrypter()
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot create paillier encrypter")
	}

	return &Verifier[P, B, S]{
		Participant: Participant[P, B, S]{
			pk:         publicKey,
			bigQ:       bigQ,
			round:      1,
			sessionId:  sessionId,
			transcript: tape,
			prng:       prng,
		},
		rangeVerifier:     rangeVerifier,
		c:                 xEncrypted,
		commitmentScheme:  commitmentScheme,
		paillierEncrypter: paillierEncrypter,
		state: &VerifierState[P, B, S]{
			State: State[P, B, S]{
				curve:  curve,
				zModQ:  q,
				zModQ2: q2,
			},
		},
	}, nil
}

func validateVerifierInputs[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](publicKey *paillier.PublicKey, bigQ P, xEncrypted *paillier.Ciphertext, prng io.Reader) error {
	if publicKey == nil {
		return ErrInvalidArgument.WithMessage("public key is nil")
	}
	if publicKey.N().BitLen() < paillier.KeyLen {
		return ErrInvalidArgument.WithMessage("invalid paillier public key: modulus is too small")
	}
	if xEncrypted == nil {
		return ErrInvalidArgument.WithMessage("xEncrypted is nil")
	}
	if utils.IsNil(bigQ) {
		return ErrInvalidArgument.WithMessage("bigQ is nil")
	}
	if prng == nil {
		return ErrInvalidArgument.WithMessage("prng is nil")
	}
	return nil
}

// NewProver constructs a prover instance for the LPDL protocol.
func NewProver[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](sessionId network.SID, curve curves.Curve[P, B, S], secretKey *paillier.PrivateKey, x S, r *paillier.Nonce, tape transcripts.Transcript, prng io.Reader) (verifier *Prover[P, B, S], err error) {
	if err = validateProverInputs(sessionId, curve, secretKey, x, r, prng); err != nil {
		return nil, errs2.Wrap(err).WithMessage("invalid input arguments")
	}

	if tape == nil {
		tape = hagrid.NewTranscript(appTranscriptLabel)
	}
	dst := fmt.Sprintf("%s-%d", sessionIdTranscriptLabel, sessionId)
	tape.AppendDomainSeparator(dst)

	rangeProofTranscript := tape.Clone()
	rangeProtocol, q, qSquared, qThirdNat, err := initRangeProtocol(curve, prng)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("couldn't initialise range protocol")
	}

	qThirdAsPlaintext, err := secretKey.PublicKey().PlaintextSpace().FromNat(qThirdNat)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("couldn't convert q/3 to plaintext")
	}

	xNat := numct.NewNatFromBytes(x.Bytes())
	xAsPlaintext, err := secretKey.PublicKey().PlaintextSpace().FromNat(xNat)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("couldn't convert x to plaintext")
	}
	rangePlainText := xAsPlaintext.Sub(qThirdAsPlaintext)

	ck, err := hash_comm.NewKeyFromCRSBytes(sessionId, appTranscriptLabel)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot instantiate committer")
	}
	commitmentScheme, err := hash_comm.NewScheme(ck)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot instantiate commitment scheme")
	}

	senc, err := paillier.NewScheme().SelfEncrypter(secretKey)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("couldn't create self-encrypter")
	}

	rangeCipherText, err := senc.SelfEncryptWithNonce(rangePlainText, r)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("couldn't create range statement")
	}
	rangeWitness := paillierrange.NewWitness(secretKey, rangePlainText, r)
	rangeStatement := paillierrange.NewStatement(secretKey.PublicKey(), rangeCipherText, qThirdNat)
	rangeProver, err := zkcompiler.NewProver(sessionId, rangeProofTranscript, rangeProtocol, rangeStatement, rangeWitness)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("couldn't initialise prover")
	}

	dec, err := paillier.NewScheme().Decrypter(secretKey)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot create paillier decrypter")
	}

	return &Prover[P, B, S]{
		Participant: Participant[P, B, S]{
			pk:         secretKey.PublicKey(),
			bigQ:       curve.ScalarBaseMul(x),
			round:      2,
			sessionId:  sessionId,
			transcript: tape,
			prng:       prng,
		},
		rangeProver:       rangeProver,
		paillierDecrypter: dec,
		commitmentScheme:  commitmentScheme,
		sk:                secretKey,
		x:                 x,
		state: &ProverState[P, B, S]{
			State: State[P, B, S]{
				curve:  curve,
				zModQ:  q,
				zModQ2: qSquared,
			},
		},
	}, nil
}

func validateProverInputs[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](sessionId network.SID, curve curves.Curve[P, B, S], secretKey *paillier.PrivateKey, x S, r *paillier.Nonce, prng io.Reader) error { //nolint:unparam // sessionId is used!
	if len(sessionId) == 0 {
		return ErrInvalidArgument.WithMessage("sessionId is empty")
	}
	if secretKey == nil {
		return ErrInvalidArgument.WithMessage("secret key is nil")
	}
	if secretKey.Group().N().AnnouncedLen() < base.IFCKeyLength {
		return ErrInvalidArgument.WithMessage("invalid paillier public key: modulus is too small")
	}
	if curve == nil {
		return ErrInvalidArgument.WithMessage("curve is nil")
	}
	if utils.IsNil(x) {
		return ErrInvalidArgument.WithMessage("x is nil")
	}
	sf := algebra.StructureMustBeAs[algebra.PrimeField[S]](x.Structure())
	if curve.ScalarField().Name() != sf.Name() {
		return ErrInvalidArgument.WithMessage("x is not an element of the scalar field of the curve")
	}
	if r == nil {
		return ErrInvalidArgument.WithMessage("r is nil")
	}
	if prng == nil {
		return ErrInvalidArgument.WithMessage("prng is nil")
	}
	return nil
}

func initRangeProtocol[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](curve curves.Curve[P, B, S], prng io.Reader) (rangeProtocol *paillierrange.Protocol, zModQ, zModQ2 *num.ZMod, qThird *numct.Nat, err error) {
	q := curve.Order()
	q2 := q.Mul(q)

	zModQ, err = num.NewZModFromCardinal(q)
	if err != nil {
		return nil, nil, nil, nil, errs2.Wrap(err).WithMessage("cannot create ZMod from q")
	}
	zModQ2, err = num.NewZModFromCardinal(q2)
	if err != nil {
		return nil, nil, nil, nil, errs2.Wrap(err).WithMessage("cannot create ZMod from q^2")
	}

	three := numct.NewNat(3)
	qNat := numct.NewNatFromBytes(q.Bytes())
	qThird = numct.NewNat(0)
	qThird.EuclideanDivVarTime(nil, qNat, three)

	rangeProtocol, err = paillierrange.NewPaillierRange(base.ComputationalSecurityBits, prng)
	if err != nil {
		return nil, nil, nil, nil, errs2.Wrap(err).WithMessage("couldn't create range protocol")
	}
	return rangeProtocol, zModQ, zModQ2, qThird, nil
}
