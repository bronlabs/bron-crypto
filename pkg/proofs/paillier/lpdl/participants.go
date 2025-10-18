package lpdl

import (
	"fmt"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	hashcommitments "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/paillier/lp"
	paillierrange "github.com/bronlabs/bron-crypto/pkg/proofs/paillier/range"
	zkcompiler "github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/zk"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
)

const (
	appTranscriptLabel       = "BRON_CRYPTO_PAILLIER_LPDL-"
	sessionIdTranscriptLabel = "BRON_CRYPTO_PAILLIER_LPDL_SESSION_ID"
)

type Participant[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	pk         *paillier.PublicKey
	bigQ       P
	round      int
	sessionId  network.SID
	transcript transcripts.Transcript
	prng       io.Reader

	base.IncomparableTrait
}

type State[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	curve  curves.Curve[P, B, S]
	zModQ  *num.ZMod
	zModQ2 *num.ZMod
	a      *num.Uint
	b      *num.Uint

	base.IncomparableTrait
}

type VerifierState[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	State[P, B, S]
	cDoublePrimeWitness hashcommitments.Witness
	bigQPrime           P
	cHat                hashcommitments.Commitment

	base.IncomparableTrait
}

type Verifier[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	Participant[P, B, S]
	rangeVerifier     *zkcompiler.Verifier[*paillierrange.Statement, *paillierrange.Witness, *paillierrange.Commitment, *paillierrange.State, *paillierrange.Response]
	paillierEncrypter *paillier.Encrypter
	c                 *paillier.Ciphertext
	state             *VerifierState[P, B, S]
	commitmentScheme  *hash_comm.Scheme

	base.IncomparableTrait
}

type ProverState[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	State[P, B, S]
	alpha                  *paillier.Plaintext
	bigQHat                P
	bigQHatWitness         hashcommitments.Witness
	cDoublePrimeCommitment hashcommitments.Commitment

	base.IncomparableTrait
}

type Prover[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	Participant[P, B, S]
	rangeProver       *zkcompiler.Prover[*paillierrange.Statement, *paillierrange.Witness, *paillierrange.Commitment, *paillierrange.State, *paillierrange.Response]
	paillierDecrypter *paillier.Decrypter
	sk                *paillier.PrivateKey
	x                 S
	state             *ProverState[P, B, S]
	commitmentScheme  *hash_comm.Scheme

	base.IncomparableTrait
}

func NewVerifier[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](sessionId network.SID, publicKey *paillier.PublicKey, bigQ P, xEncrypted *paillier.Ciphertext, tape transcripts.Transcript, prng io.Reader) (verifier *Verifier[P, B, S], err error) {
	err = validateVerifierInputs(sessionId, publicKey, bigQ, xEncrypted, prng)
	if err != nil {
		return nil, errs.WrapArgument(err, "invalid input arguments")
	}

	curve := algebra.StructureMustBeAs[curves.Curve[P, B, S]](bigQ.Structure())

	if tape == nil {
		tape = hagrid.NewTranscript(appTranscriptLabel)
	}
	dst := fmt.Sprintf("%s-%d", sessionIdTranscriptLabel, sessionId)
	tape.AppendDomainSeparator(dst)

	rangeProofTranscript := tape.Clone()
	rangeProtocol, q, q2, qThirdNat, err := initRangeProtocol(curve, publicKey, rangeProofTranscript, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't initialise range protocol")
	}

	// Create Phi(q/3) for homomorphic division
	var qThirdInt numct.Int
	qThirdInt.SetNat(qThirdNat)
	qThirdUnit, err := publicKey.Group().Phi(&qThirdInt)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot compute Phi(q/3)")
	}
	qThird := paillier.NewCiphertextFromUnit(qThirdUnit)

	// xEncrypted has known order, qThird has unknown order from Phi
	// Need to forget order on xEncrypted for the division
	xUnknown := paillier.NewCiphertextFromUnit(xEncrypted.Value().ForgetOrder())
	rangeCiphertext := xUnknown.Div(qThird)
	rangeStatement := paillierrange.NewStatement(publicKey, rangeCiphertext, qThirdNat)
	rangeVerifier, err := zkcompiler.NewVerifier(sessionId, rangeProofTranscript, rangeProtocol, rangeStatement, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create Paillier range verifier")
	}

	ck, err := hash_comm.NewKeyFromCRSBytes(sessionId, appTranscriptLabel)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot instantiate committer")
	}
	commitmentScheme, err := hash_comm.NewScheme(ck)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot instantiate commitment scheme")
	}

	paillierEncrypter, err := paillier.NewScheme().Encrypter()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create paillier encrypter")
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

func validateVerifierInputs[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](sessionId network.SID, publicKey *paillier.PublicKey, bigQ P, xEncrypted *paillier.Ciphertext, prng io.Reader) error {
	if len(sessionId) == 0 {
		return errs.NewIsNil("sessionId is nil")
	}
	if publicKey == nil {
		return errs.NewIsNil("public key is nil")
	}
	if publicKey.N().BitLen() < lp.PaillierBitSize {
		return errs.NewArgument("invalid paillier public key: modulus is too small")
	}
	if xEncrypted == nil {
		return errs.NewIsNil("xEncrypted is nil")
	}
	if v := xEncrypted.ValueCT(); v.IsZero()&v.Equal(numct.NatOne()) == ct.True {
		return errs.NewArgument("xEncrypted is invalid: %s", v.String())
	}
	if prng == nil {
		return errs.NewIsNil("prng is nil")
	}
	return nil
}

func NewProver[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](sessionId network.SID, curve curves.Curve[P, B, S], secretKey *paillier.PrivateKey, x S, r *paillier.Nonce, tape transcripts.Transcript, prng io.Reader) (verifier *Prover[P, B, S], err error) {
	if err = validateProverInputs(sessionId, curve, secretKey, x, r, prng); err != nil {
		return nil, errs.WrapArgument(err, "invalid input arguments")
	}

	if tape == nil {
		tape = hagrid.NewTranscript(appTranscriptLabel)
	}
	dst := fmt.Sprintf("%s-%d", sessionIdTranscriptLabel, sessionId)
	tape.AppendDomainSeparator(dst)

	rangeProofTranscript := tape.Clone()
	rangeProtocol, q, qSquared, qThirdNat, err := initRangeProtocol(curve, secretKey.PublicKey(), rangeProofTranscript, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't initialise range protocol")
	}

	qThirdAsPlaintext, err := secretKey.PublicKey().PlaintextSpace().FromNat(qThirdNat)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't convert q/3 to plaintext")
	}

	xNat := numct.NewNatFromBytes(x.Bytes())
	xAsPlaintext, err := secretKey.PublicKey().PlaintextSpace().FromNat(xNat)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't convert x to plaintext")
	}
	rangePlainText := xAsPlaintext.Sub(qThirdAsPlaintext)

	ck, err := hash_comm.NewKeyFromCRSBytes(sessionId, appTranscriptLabel)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot instantiate committer")
	}
	commitmentScheme, err := hash_comm.NewScheme(ck)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot instantiate commitment scheme")
	}

	senc, err := paillier.NewScheme().SelfEncrypter(secretKey)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't create self-encrypter")
	}

	rangeCipherText, err := senc.SelfEncryptWithNonce(rangePlainText, r)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't create range statement")
	}
	rangeWitness := paillierrange.NewWitness(secretKey, rangePlainText, r)
	rangeStatement := paillierrange.NewStatement(secretKey.PublicKey(), rangeCipherText, qThirdNat)
	rangeProver, err := zkcompiler.NewProver(sessionId, rangeProofTranscript, rangeProtocol, rangeStatement, rangeWitness)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't initialise prover")
	}

	dec, err := paillier.NewScheme().Decrypter(secretKey)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create paillier decrypter")
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

func validateProverInputs[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](sessionId network.SID, curve curves.Curve[P, B, S], secretKey *paillier.PrivateKey, x S, r *paillier.Nonce, prng io.Reader) error {
	if len(sessionId) == 0 {
		return errs.NewIsNil("sessionId is nil")
	}
	if secretKey == nil {
		return errs.NewIsNil("secret key is nil")
	}
	if secretKey.Group().N().AnnouncedLen() < lp.PaillierBitSize {
		return errs.NewSize("invalid paillier public key: modulus is too small")
	}
	if curve == nil {
		return errs.NewIsNil("curve is nil")
	}
	if utils.IsNil(x) {
		return errs.NewIsNil("x is nil")
	}
	sf := algebra.StructureMustBeAs[algebra.PrimeField[S]](x.Structure())
	if curve.ScalarField().Name() != sf.Name() {
		return errs.NewArgument("x is not an element of the scalar field of the curve")
	}
	if r == nil {
		return errs.NewIsNil("r is nil")
	}
	if prng == nil {
		return errs.NewIsNil("prng is nil")
	}
	return nil
}

func initRangeProtocol[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](curve curves.Curve[P, B, S], publicKey *paillier.PublicKey, tape transcripts.Transcript, prng io.Reader) (rangeProtocol *paillierrange.Protocol, zModQ, zModQ2 *num.ZMod, qThird *numct.Nat, err error) {
	q := curve.Order()
	q2 := q.Mul(q)

	zModQ, err = num.NewZModFromCardinal(q)
	if err != nil {
		return nil, nil, nil, nil, errs.WrapFailed(err, "cannot create ZMod from q")
	}
	zModQ2, err = num.NewZModFromCardinal(q2)
	if err != nil {
		return nil, nil, nil, nil, errs.WrapFailed(err, "cannot create ZMod from q^2")
	}

	three, ok := numct.NewModulus(numct.NewNat(3))
	if ok == ct.False {
		panic("cannot create modulus 3")
	}
	qNat := numct.NewNatFromBytes(q.Bytes())
	qThird = numct.NewNat(0)
	qThird.DivCap(qNat, three, int(q.BitLen()))

	rangeProtocol, err = paillierrange.NewPaillierRange(base.ComputationalSecurityBits, prng)
	if err != nil {
		return nil, nil, nil, nil, errs.WrapFailed(err, "couldn't create range protocol")
	}
	return rangeProtocol, zModQ, zModQ2, qThird, nil
}
