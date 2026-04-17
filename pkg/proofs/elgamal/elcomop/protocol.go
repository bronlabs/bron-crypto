package elcomop

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/constructions"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/commitments/indcpacom"
	"github.com/bronlabs/bron-crypto/pkg/encryption/elgamal"
	"github.com/bronlabs/bron-crypto/pkg/proofs/internal/meta/maurer09"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	"github.com/bronlabs/errs-go/errs"
)

const Name sigma.Name = "PROOF_OF_KNOWLEDGE_OF_OPENING_OF_ELGAMAL_IN_EXPONENT_COMMITMENT"

type (
	Witness[S algebra.PrimeFieldElement[S]]                                       = maurer09.Witness[*constructions.FiniteDirectPowerRingElement[S]]
	Statement[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]]  = maurer09.Statement[*constructions.FiniteDirectPowerModuleElement[G, S]]
	State[S algebra.PrimeFieldElement[S]]                                         = maurer09.State[*constructions.FiniteDirectPowerRingElement[S]]
	Commitment[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] = maurer09.Commitment[*constructions.FiniteDirectPowerModuleElement[G, S]]
	Response[S algebra.PrimeFieldElement[S]]                                      = maurer09.Response[*constructions.FiniteDirectPowerRingElement[S]]
)

func NewWitness[S algebra.PrimeFieldElement[S]](lambda *indcpacom.Witness[*elgamal.Nonce[S]], y *indcpacom.Message[S]) (*Witness[S], error) {
	if lambda == nil || lambda.Value() == nil || utils.IsNil(lambda.Value().Value()) || y == nil || utils.IsNil(y.Value()) {
		return nil, ErrInvalidArgument.WithMessage("witness values cannot be nil")
	}
	baseRing := algebra.StructureMustBeAs[algebra.PrimeField[S]](lambda.Value().Value().Structure())
	powerRing, err := constructions.NewFiniteDirectPowerRing(baseRing, 2)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create direct power ring")
	}
	witnessValue, err := powerRing.New(lambda.Value().Value(), y.Value())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create witness element")
	}
	return &Witness[S]{W: witnessValue}, nil
}

func NewStatement[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](x *indcpacom.Commitment[*elgamal.Ciphertext[G, S], *elgamal.Nonce[S], *elgamal.PublicKey[G, S]]) (*Statement[G, S], error) {
	if x == nil || x.Value() == nil || utils.IsNil(x.Value().Value()) {
		return nil, ErrInvalidArgument.WithMessage("statement values cannot be nil")
	}
	return &Statement[G, S]{X: x.Value().Value()}, nil
}

type Protocol[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	*maurer09.Protocol[
		*constructions.FiniteDirectPowerModuleElement[G, S],
		*constructions.FiniteDirectPowerRingElement[S],
	]
}

func NewProtocol[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](group algebra.PrimeGroup[G, S], key *indcpacom.Key[*elgamal.PublicKey[G, S]], prng io.Reader) (*Protocol[G, S], error) {
	if group == nil || key == nil || prng == nil {
		return nil, ErrInvalidArgument.WithMessage("group, key, and prng cannot be nil")
	}
	generator := group.Generator()
	baseScalarField := algebra.StructureMustBeAs[algebra.PrimeField[S]](group.ScalarStructure())

	scalarPowerRing, err := constructions.NewFiniteDirectPowerRing(baseScalarField, 2)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create scalar power ring")
	}

	powerModule, err := constructions.NewFiniteDirectPowerModule(group, 2)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create power group")
	}

	enc, err := elgamal.NewScheme(group)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create ElGamal scheme")
	}
	comScheme, err := indcpacom.NewScheme(enc, key)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create IND-CPA commitment scheme")
	}
	committer, err := comScheme.Committer()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create commitment committer")
	}

	homomorphism := func(w *constructions.FiniteDirectPowerRingElement[S]) *constructions.FiniteDirectPowerModuleElement[G, S] {
		comps := w.Components()
		nonce, err := elgamal.NewNonce(comps[0])
		if err != nil {
			panic(err)
		}
		witness, err := indcpacom.NewWitness(nonce)
		if err != nil {
			panic(err)
		}
		plaintext, err := elgamal.NewPlaintext(generator.ScalarOp(comps[1]))
		if err != nil {
			panic(err)
		}
		message, err := indcpacom.NewMessage(plaintext)
		if err != nil {
			panic(err)
		}
		commitment, err := committer.CommitWithWitness(message, witness)
		if err != nil {
			panic(err)
		}
		return commitment.Value().Value()
	}

	challengeByteLen := base.ComputationalSecurityBytesCeil
	soundnessError := uint(challengeByteLen * 8)

	l, err := num.N().FromBytes(group.Order().Bytes())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create anchor")
	}
	anc := &anchor[G, S]{l, scalarPowerRing.Zero()}

	maurerProtocol, err := maurer09.NewProtocol(
		challengeByteLen,
		soundnessError,
		Name,
		powerModule,
		scalarPowerRing,
		homomorphism,
		anc,
		prng,
	)
	if err != nil {
		return nil, errs.Wrap(err)
	}

	return &Protocol[G, S]{maurerProtocol}, nil

}

type anchor[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	l  *num.Nat
	id *constructions.FiniteDirectPowerRingElement[S]
}

func (a *anchor[G, S]) L() *num.Nat {
	return a.l
}

func (a *anchor[G, S]) PreImage(_ *constructions.FiniteDirectPowerModuleElement[G, S]) (w *constructions.FiniteDirectPowerRingElement[S]) {
	return a.id
}
