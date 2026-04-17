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

const Name sigma.Name = "PROOF_OF_KNOWLEDGE_OF_OPENING_OF_ELGAMAL_COMMITMENT"

type (
	Witness[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]]    = maurer09.Witness[*constructions.FiniteDirectProductGroupElement[G, S]]
	Statement[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]]  = maurer09.Statement[*constructions.FiniteDirectPowerModuleElement[G, S]]
	State[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]]      = maurer09.State[*constructions.FiniteDirectProductGroupElement[G, S]]
	Commitment[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] = maurer09.Commitment[*constructions.FiniteDirectPowerModuleElement[G, S]]
	Response[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]]   = maurer09.Response[*constructions.FiniteDirectProductGroupElement[G, S]]
)

func NewWitness[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](message *indcpacom.Message[*elgamal.Plaintext[G, S]], nonce *indcpacom.Witness[*elgamal.Nonce[S]]) (*Witness[G, S], error) {
	if nonce == nil || nonce.Value() == nil || utils.IsNil(nonce.Value().Value()) || message == nil || message.Value() == nil || utils.IsNil(message.Value().Value()) {
		return nil, ErrInvalidArgument.WithMessage("witness values cannot be nil")
	}
	g1 := algebra.StructureMustBeAs[algebra.PrimeGroup[G, S]](message.Value().Value().Structure())
	g2 := algebra.StructureMustBeAs[algebra.PrimeField[S]](nonce.Value().Value().Structure())
	powerRing, err := constructions.NewFiniteDirectProductGroup(g1, g2)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create direct power group")
	}
	witnessValue, err := powerRing.New(message.Value().Value(), nonce.Value().Value())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create witness element")
	}
	return &Witness[G, S]{W: witnessValue}, nil
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
		*constructions.FiniteDirectProductGroupElement[G, S],
	]
}

func NewProtocol[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](group algebra.PrimeGroup[G, S], key *indcpacom.Key[*elgamal.PublicKey[G, S]], prng io.Reader) (*Protocol[G, S], error) {
	if group == nil || key == nil || prng == nil {
		return nil, ErrInvalidArgument.WithMessage("group, key, and prng cannot be nil")
	}
	scalarField := algebra.StructureMustBeAs[algebra.PrimeField[S]](group.ScalarStructure())

	preImageGroup, err := constructions.NewFiniteDirectProductGroup(group, scalarField)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create pre-image group")
	}

	imageGroup, err := constructions.NewFiniteDirectPowerModule(group, 2)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create image group")
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

	homomorphism := func(w *constructions.FiniteDirectProductGroupElement[G, S]) (*constructions.FiniteDirectPowerModuleElement[G, S], error) {
		messageValue, nonceValue := w.Components()
		nonce, err := elgamal.NewNonce(nonceValue)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to create nonce from homomorphism input")
		}
		witness, err := indcpacom.NewWitness(nonce)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to create commitment witness from homomorphism input")
		}
		plaintext, err := elgamal.NewPlaintext(messageValue)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to create plaintext from homomorphism input")
		}
		message, err := indcpacom.NewMessage(plaintext)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to create commitment message from homomorphism input")
		}
		commitment, err := committer.CommitWithWitness(message, witness)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to compute commitment from homomorphism input")
		}
		return commitment.Value().Value(), nil
	}

	challengeByteLen := base.ComputationalSecurityBytesCeil
	soundnessError := uint(challengeByteLen * 8)

	l, err := num.N().FromBytes(group.Order().Bytes())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create anchor")
	}
	anc := &anchor[G, S]{l, preImageGroup.OpIdentity()}

	maurerProtocol, err := maurer09.NewProtocol(
		challengeByteLen,
		soundnessError,
		Name,
		imageGroup,
		preImageGroup,
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
	id *constructions.FiniteDirectProductGroupElement[G, S]
}

func (a *anchor[G, S]) L() *num.Nat {
	return a.l
}

func (a *anchor[G, S]) PreImage(_ *constructions.FiniteDirectPowerModuleElement[G, S]) (w *constructions.FiniteDirectProductGroupElement[G, S]) {
	return a.id
}
