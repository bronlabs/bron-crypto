package lpdl

import (
	"encoding/hex"
	"fmt"
	"io"
	"slices"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/commitments/hashcom"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/proofs"
	paillierrange "github.com/bronlabs/bron-crypto/pkg/proofs/paillier/range"
	zkcompiler "github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/zk"
)

const (
	appTranscriptLabel       = "BRON_CRYPTO_PAILLIER_LPDL-"
	sessionIDTranscriptLabel = "BRON_CRYPTO_PAILLIER_LPDL_SESSION_ID"
)

// Participant holds common state for the LPDL protocol participants.
type Participant[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	ctx       *session.Context
	copartyID sharing.ID
	round     int
	pk        *paillier.PublicKey
	bigQ      P
	prng      io.Reader
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

	cDoublePrimeWitness hashcom.Witness
	bigQPrime           P
	cHat                hashcom.Commitment
}

// Verifier runs the LPDL verifier role.
type Verifier[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	Participant[P, B, S]

	rangeVerifier *zkcompiler.Verifier[*paillierrange.Statement, *paillierrange.Witness, *paillierrange.Commitment, *paillierrange.State, *paillierrange.Response]
	c             *paillier.Ciphertext
	state         *VerifierState[P, B, S]
	commitmentKey *hashcom.CommitmentKey
}

// ProverState tracks the prover's internal state across rounds.
type ProverState[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	State[P, B, S]

	alpha                  *paillier.Plaintext
	bigQHat                P
	bigQHatWitness         hashcom.Witness
	cDoublePrimeCommitment hashcom.Commitment
}

// Prover runs the LPDL prover role.
type Prover[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	Participant[P, B, S]

	rangeProver   *zkcompiler.Prover[*paillierrange.Statement, *paillierrange.Witness, *paillierrange.Commitment, *paillierrange.State, *paillierrange.Response]
	sk            *paillier.SecretKey
	x             S
	state         *ProverState[P, B, S]
	commitmentKey *hashcom.CommitmentKey
}

// NewVerifier constructs a verifier instance for the LPDL protocol.
func NewVerifier[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](ctx *session.Context, publicKey *paillier.PublicKey, bigQ P, xEncrypted *paillier.Ciphertext, prng io.Reader) (verifier *Verifier[P, B, S], err error) {
	err = validateVerifierInputs(ctx, publicKey, bigQ, xEncrypted, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid input arguments")
	}

	curve := algebra.StructureMustBeAs[curves.Curve[P, B, S]](bigQ.Structure())

	copartyID := slices.Collect(ctx.OtherPartiesOrdered())[0]
	sid := ctx.SessionID()
	dst := fmt.Sprintf("%s-%s", sessionIDTranscriptLabel, hex.EncodeToString(sid[:]))
	ctx.Transcript().AppendDomainSeparator(dst)

	rangeProtocol, q, q2, qThirdUint, err := initRangeProtocol(curve, publicKey, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("couldn't initialise range protocol")
	}

	// Create Phi(q/3) for homomorphic division
	qThirdUnit, err := publicKey.Group().Representative(qThirdUint)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot compute Phi(q/3)")
	}
	qThird, err := paillier.NewCiphertextFromGroupElement(qThirdUnit)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create ciphertext for q/3")
	}

	// xEncrypted has known order, qThird has unknown order from Phi
	// Need to forget order on xEncrypted for the division
	xUnknown, err := paillier.NewCiphertextFromGroupElement(xEncrypted.Value())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create ciphertext for xEncrypted")
	}
	qThirdInv, err := publicKey.CiphertextOpInv(qThird)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot compute inverse of qThird")
	}
	rangeCiphertext, err := publicKey.CiphertextOp(xUnknown, qThirdInv)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot compute range ciphertext")
	}
	rangeStatement, err := paillierrange.NewStatement(rangeCiphertext)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create range statement")
	}
	rangeVerifier, err := zkcompiler.NewVerifier(ctx, rangeProtocol, rangeStatement, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create Paillier range verifier")
	}

	ck, err := hashcom.ExtractCommitmentKey(ctx.Transcript(), appTranscriptLabel)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot extract commitment key")
	}

	return &Verifier[P, B, S]{
		Participant: Participant[P, B, S]{
			ctx:       ctx,
			copartyID: copartyID,
			round:     1,
			pk:        publicKey,
			bigQ:      bigQ,
			prng:      prng,
		},
		rangeVerifier: rangeVerifier,
		c:             xEncrypted,
		commitmentKey: ck,
		state: &VerifierState[P, B, S]{
			State: State[P, B, S]{
				curve:  curve,
				zModQ:  q,
				zModQ2: q2,
				a:      nil,
				b:      nil,
			},
			cDoublePrimeWitness: hashcom.Witness{},
			bigQPrime:           *new(P),
			cHat:                hashcom.Commitment{},
		},
	}, nil
}

func validateVerifierInputs[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](ctx *session.Context, publicKey *paillier.PublicKey, bigQ P, xEncrypted *paillier.Ciphertext, prng io.Reader) error {
	if ctx == nil {
		return proofs.ErrInvalidArgument.WithMessage("context is nil")
	}
	if ctx.Quorum().Size() != 2 {
		return proofs.ErrInvalidArgument.WithMessage("invalid quorum size")
	}
	if publicKey == nil {
		return proofs.ErrInvalidArgument.WithMessage("public key is nil")
	}
	if xEncrypted == nil {
		return proofs.ErrInvalidArgument.WithMessage("xEncrypted is nil")
	}
	if utils.IsNil(bigQ) {
		return proofs.ErrInvalidArgument.WithMessage("bigQ is nil")
	}
	if prng == nil {
		return proofs.ErrInvalidArgument.WithMessage("prng is nil")
	}
	return nil
}

// NewProver constructs a prover instance for the LPDL protocol.
func NewProver[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](ctx *session.Context, curve curves.Curve[P, B, S], secretKey *paillier.SecretKey, x S, r *paillier.Nonce, prng io.Reader) (verifier *Prover[P, B, S], err error) {
	if err = validateProverInputs(ctx, curve, secretKey, x, r, prng); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid input arguments")
	}

	copartyID := slices.Collect(ctx.OtherPartiesOrdered())[0]
	sid := ctx.SessionID()
	dst := fmt.Sprintf("%s-%s", sessionIDTranscriptLabel, hex.EncodeToString(sid[:]))
	ctx.Transcript().AppendDomainSeparator(dst)

	rangeProtocol, q, qSquared, qThirdUint, err := initRangeProtocol(curve, secretKey, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("couldn't initialise range protocol")
	}

	qThirdAsPlaintext, err := paillier.NewPlaintext(qThirdUint)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("couldn't convert q/3 to plaintext")
	}
	qThirdAsPlaintextInv, err := secretKey.PlaintextOpInv(qThirdAsPlaintext)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("couldn't compute inverse of q/3 plaintext")
	}

	xNat := numct.NewNatFromBytes(x.Bytes())
	xUint, err := num.NewUintGivenModulus(xNat, secretKey.PlaintextGroup().ModulusCT())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("couldn't convert x to uint")
	}
	xAsPlaintext, err := paillier.NewPlaintext(xUint)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("couldn't convert x to plaintext")
	}
	rangePlainText, err := secretKey.PlaintextOp(xAsPlaintext, qThirdAsPlaintextInv)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("couldn't compute range plaintext")
	}

	rangeCipherText, err := secretKey.EncryptWithNonce(rangePlainText, r)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("couldn't create range statement")
	}
	rangeWitness, err := paillierrange.NewWitness(rangePlainText, r)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("couldn't create range witness")
	}
	rangeStatement, err := paillierrange.NewStatement(rangeCipherText)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("couldn't create range statement")
	}
	rangeProver, err := zkcompiler.NewProver(ctx, rangeProtocol, rangeStatement, rangeWitness)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("couldn't initialise prover")
	}

	ck, err := hashcom.ExtractCommitmentKey(ctx.Transcript(), appTranscriptLabel)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot extract commitment key")
	}

	return &Prover[P, B, S]{
		Participant: Participant[P, B, S]{
			ctx:       ctx,
			copartyID: copartyID,
			round:     2,
			pk:        secretKey.Public(),
			bigQ:      curve.ScalarBaseMul(x),
			prng:      prng,
		},
		rangeProver:   rangeProver,
		commitmentKey: ck,
		sk:            secretKey,
		x:             x,
		state: &ProverState[P, B, S]{
			State: State[P, B, S]{
				curve:  curve,
				zModQ:  q,
				zModQ2: qSquared,
				a:      nil,
				b:      nil,
			},
			alpha:                  nil,
			bigQHat:                *new(P),
			bigQHatWitness:         hashcom.Witness{},
			cDoublePrimeCommitment: hashcom.Commitment{},
		},
	}, nil
}

func validateProverInputs[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](ctx *session.Context, curve curves.Curve[P, B, S], secretKey *paillier.SecretKey, x S, r *paillier.Nonce, prng io.Reader) error {
	if ctx == nil {
		return proofs.ErrInvalidArgument.WithMessage("ctx is empty")
	}
	if ctx.Quorum().Size() != 2 {
		return proofs.ErrInvalidArgument.WithMessage("invalid quorum size")
	}
	if secretKey == nil {
		return proofs.ErrInvalidArgument.WithMessage("secret key is nil")
	}
	if curve == nil {
		return proofs.ErrInvalidArgument.WithMessage("curve is nil")
	}
	if utils.IsNil(x) {
		return proofs.ErrInvalidArgument.WithMessage("x is nil")
	}
	sf := algebra.StructureMustBeAs[algebra.PrimeField[S]](x.Structure())
	if curve.ScalarField().Name() != sf.Name() {
		return proofs.ErrInvalidArgument.WithMessage("x is not an element of the scalar field of the curve")
	}
	if r == nil {
		return proofs.ErrInvalidArgument.WithMessage("r is nil")
	}
	if prng == nil {
		return proofs.ErrInvalidArgument.WithMessage("prng is nil")
	}
	return nil
}

func initRangeProtocol[EK paillier.EncryptionKey[EK], P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](curve curves.Curve[P, B, S], encryptionKey EK, prng io.Reader) (rangeProtocol *paillierrange.Protocol[EK], zModQ, zModQ2 *num.ZMod, qThird *num.Uint, err error) {
	q := curve.Order()
	q2 := q.Mul(q)

	zModQ, err = num.NewZModFromCardinal(q)
	if err != nil {
		return nil, nil, nil, nil, errs.Wrap(err).WithMessage("cannot create ZMod from q")
	}
	zModQ2, err = num.NewZModFromCardinal(q2)
	if err != nil {
		return nil, nil, nil, nil, errs.Wrap(err).WithMessage("cannot create ZMod from q^2")
	}

	three := numct.NewNat(3)
	qNat := numct.NewNatFromBytes(q.Bytes())
	qThirdNat := numct.NewNat(0)
	qThirdNat.EuclideanDivVarTime(nil, qNat, three)

	qThird, err = num.NewUintGivenModulus(qThirdNat, encryptionKey.PlaintextGroup().ModulusCT())
	if err != nil {
		return nil, nil, nil, nil, errs.Wrap(err).WithMessage("cannot create NPlus from NatCT")
	}

	qThirdNatPlus, err := num.NPlus().FromNat(qThird.Nat())
	if err != nil {
		return nil, nil, nil, nil, errs.Wrap(err).WithMessage("cannot convert q/3 to NatPlus")
	}

	rangeProtocol, err = paillierrange.NewPaillierRange(base.ComputationalSecurityBits, qThirdNatPlus, encryptionKey, prng)
	if err != nil {
		return nil, nil, nil, nil, errs.Wrap(err).WithMessage("couldn't create range protocol")
	}
	return rangeProtocol, zModQ, zModQ2, qThird, nil
}
