package vanilla

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/signatures"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorr"
)

type (
	PublicKey[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S]]  = schnorr.PublicKey[GE, S]
	PrivateKey[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S]] = schnorr.PrivateKey[GE, S]
	Signature[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S]]  = schnorr.Signature[GE, S]
)

const VariantType schnorr.VariantType = "vanilla"

func NewPublicKey[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S]](point GE) (*PublicKey[GE, S], error) {
	return schnorr.NewPublicKey(point)
}

func NewPrivateKey[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S]](scalar S, pk *PublicKey[GE, S]) (*PrivateKey[GE, S], error) {
	return schnorr.NewPrivateKey(scalar, pk)
}

func NewScheme[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S]](
	group algebra.PrimeGroup[GE, S],
	responseOperatorIsNegative bool,
	challengeElementsAreLittleEndian bool,
) (*Scheme[GE, S], error) {
	if group == nil {
		return nil, errs.NewIsNil("group")
	}
	sf, ok := group.ScalarStructure().(algebra.PrimeField[S])
	if !ok {
		return nil, errs.NewType("group")
	}
	return &Scheme[GE, S]{
		group:                            group,
		sf:                               sf,
		responseOperatorIsNegative:       responseOperatorIsNegative,
		challengeElementsAreLittleEndian: challengeElementsAreLittleEndian,
	}, nil
}

type Scheme[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S]] struct {
	group                            algebra.PrimeGroup[GE, S]
	sf                               algebra.PrimeField[S]
	responseOperatorIsNegative       bool
	challengeElementsAreLittleEndian bool
}

func (*Scheme[GE, S]) Name() signatures.Name {
	return schnorr.Name
}

func (s *Scheme[GE, S]) Keygen(opts ...KeyGeneratorOption[GE, S]) (*KeyGenerator[GE, S], error) {
	out := &KeyGenerator[GE, S]{
		KeyGeneratorTrait: schnorr.KeyGeneratorTrait[GE, S]{
			Grp: s.group,
			SF:  s.sf,
		},
	}
	for _, opt := range opts {
		if err := opt(out); err != nil {
			return nil, errs.WrapFailed(err, "key generator option failed")
		}
	}
	return out, nil
}

type KeyGeneratorOption[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S]] = signatures.KeyGeneratorOption[*KeyGenerator[GE, S], *PrivateKey[GE, S], *PublicKey[GE, S]]

type KeyGenerator[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S]] struct {
	schnorr.KeyGeneratorTrait[GE, S]
}

type SignerOption[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S], M schnorr.Message] = signatures.SignerOption[*Signer[GE, S, M], M, *Signature[GE, S]]

type Signer[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S], M schnorr.Message] struct {
	schnorr.RandomisedSignerTrait[*Variant[GE, S, M], GE, S, M]
}

type VerifierOption[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S], M schnorr.Message] = signatures.VerifierOption[*Verifier[GE, S, M], *PublicKey[GE, S], M, *Signature[GE, S]]

type Verifier[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S], M schnorr.Message] struct {
	schnorr.VerifierTrait[*Variant[GE, S, M], GE, S, M]
}

type VariantOption[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S], M schnorr.Message] = schnorr.VariantOption[*Variant[GE, S, M], GE, S, M]
type Variant[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S], M schnorr.Message] struct {
}
