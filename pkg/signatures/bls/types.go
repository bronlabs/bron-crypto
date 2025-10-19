package bls

import (
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/iterutils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/signatures"
)

const (
	Name signatures.Name = "BLS"

	Basic               RogueKeyPreventionAlgorithm = 1
	MessageAugmentation RogueKeyPreventionAlgorithm = 2
	POP                 RogueKeyPreventionAlgorithm = 3

	ShortKey Variant = 1
	LongKey  Variant = 2
)

type (
	RogueKeyPreventionAlgorithm int
	Variant                     int
	Message                     = []byte
)

type CipherSuite struct {
	FamilyName                      string
	DstSignatureBasicInTwistedGroup string
	DstSignatureAugInTwistedGroup   string
	DstSignaturePopInTwistedGroup   string
	DstPopProofInTwistedGroup       string
	DstSignatureBasicInSourceGroup  string
	DstSignatureAugInSourceGroup    string
	DstSignaturePopInSourceGroup    string
	DstPopProofInSourceGroup        string
}

func (c *CipherSuite) GetDst(alg RogueKeyPreventionAlgorithm, variant Variant) (string, error) {
	switch alg {
	case Basic:
		if variant == ShortKey {
			return (c.DstSignatureBasicInTwistedGroup), nil
		}
		return (c.DstSignatureBasicInSourceGroup), nil
	case MessageAugmentation:
		if variant == ShortKey {
			return (c.DstSignatureAugInTwistedGroup), nil
		}
		return (c.DstSignatureAugInSourceGroup), nil
	case POP:
		if variant == ShortKey {
			return (c.DstSignaturePopInTwistedGroup), nil
		}
		return (c.DstSignaturePopInSourceGroup), nil
	default:
		return "", errs.NewType("algorithm type %v not implemented", alg)
	}
}

func (c *CipherSuite) GetPopDst(variant Variant) string {
	if variant == ShortKey {
		return c.DstPopProofInSourceGroup
	}
	return c.DstPopProofInTwistedGroup
}

func BLS12381CipherSuite() *CipherSuite {
	return &CipherSuite{
		FamilyName: bls12381.FamilyName,
		// Domain separation tag for basic signatures
		// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#section-4.2.1
		DstSignatureBasicInTwistedGroup: "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_",
		// Domain separation tag for basic signatures
		// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#section-4.2.2
		DstSignatureAugInTwistedGroup: "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_",
		// Domain separation tag for proof of possession signatures
		// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#section-4.2.3
		DstSignaturePopInTwistedGroup: "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_",
		// Domain separation tag for proof of possession proofs
		// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#section-4.2.3
		DstPopProofInTwistedGroup: "BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_",
		// Domain separation tag for basic signatures
		// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#section-4.2.1
		DstSignatureBasicInSourceGroup: "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_",
		// Domain separation tag for basic signatures
		// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#section-4.2.2
		DstSignatureAugInSourceGroup: "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_AUG_",
		// Domain separation tag for proof of possession signatures
		// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#section-4.2.3
		DstSignaturePopInSourceGroup: "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_",
		// Domain separation tag for proof of possession proofs
		// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#section-4.2.3
		DstPopProofInSourceGroup: "BLS_POP_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_",
	}
}

func RogueKeyPreventionAlgorithmIsSupported(alg RogueKeyPreventionAlgorithm) bool {
	return alg == Basic || alg == MessageAugmentation || alg == POP
}

func NewPublicKey[
	PK curves.PairingFriendlyPoint[PK, PKFE, Sig, SigFE, E, S], PKFE algebra.FieldElement[PKFE],
	Sig curves.PairingFriendlyPoint[Sig, SigFE, PK, PKFE, E, S], SigFE algebra.FieldElement[SigFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](v PK) (*PublicKey[PK, PKFE, Sig, SigFE, E, S], error) {
	if v.IsOpIdentity() {
		return nil, errs.NewFailed("cannot create public key from identity point")
	}
	if !v.IsTorsionFree() {
		return nil, errs.NewFailed("cannot create public key from torsion point")
	}
	return &PublicKey[PK, PKFE, Sig, SigFE, E, S]{
		PublicKeyTrait: signatures.PublicKeyTrait[PK, S]{V: v},
	}, nil
}

func NewPublicKeyFromBytes[
	PK curves.PairingFriendlyPoint[PK, PKFE, Sig, SigFE, E, S], PKFE algebra.FieldElement[PKFE],
	Sig curves.PairingFriendlyPoint[Sig, SigFE, PK, PKFE, E, S], SigFE algebra.FieldElement[SigFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](subGroup curves.PairingFriendlyCurve[PK, PKFE, Sig, SigFE, E, S], input []byte) (*PublicKey[PK, PKFE, Sig, SigFE, E, S], error) {
	v, err := subGroup.FromBytes(input)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create public key from bytes")
	}
	return NewPublicKey(v)
}

type PublicKey[
	PK curves.PairingFriendlyPoint[PK, PKFE, Sig, SigFE, E, S], PKFE algebra.FieldElement[PKFE],
	Sig curves.PairingFriendlyPoint[Sig, SigFE, PK, PKFE, E, S], SigFE algebra.FieldElement[SigFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
] struct {
	signatures.PublicKeyTrait[PK, S]
}

func (pk *PublicKey[P1, F1, P2, F2, E, S]) Group() curves.PairingFriendlyCurve[P1, F1, P2, F2, E, S] {
	group, ok := pk.V.Structure().(curves.PairingFriendlyCurve[P1, F1, P2, F2, E, S])
	if !ok {
		panic(errs.NewType("public key value does not implement curves.Curve interface"))
	}
	return group
}

func (pk *PublicKey[P1, F1, P2, F2, E, S]) Name() signatures.Name {
	return Name
}

func (pk *PublicKey[P1, F1, P2, F2, E, S]) Clone() *PublicKey[P1, F1, P2, F2, E, S] {
	if pk == nil {
		return nil
	}
	return &PublicKey[P1, F1, P2, F2, E, S]{PublicKeyTrait: *pk.PublicKeyTrait.Clone()}
}

func (pk *PublicKey[P1, F1, P2, F2, E, S]) Equal(other *PublicKey[P1, F1, P2, F2, E, S]) bool {
	return pk != nil && other != nil && pk.PublicKeyTrait.Equal(&other.PublicKeyTrait)
}

func (pk *PublicKey[P1, F1, P2, F2, E, S]) HashCode() base.HashCode {
	return pk.PublicKeyTrait.HashCode()
}

func (pk *PublicKey[P1, F1, P2, F2, E, S]) Bytes() []byte {
	if pk == nil {
		return nil
	}
	return pk.Value().ToCompressed()
}

func (pk *PublicKey[P1, F1, P2, F2, E, S]) IsShort() bool {
	return pk.Value().InSourceGroup()
}

func (pk *PublicKey[P1, F1, P2, F2, E, S]) TryAdd(other *PublicKey[P1, F1, P2, F2, E, S]) (*PublicKey[P1, F1, P2, F2, E, S], error) {
	if other == nil {
		return nil, errs.NewIsNil("cannot add nil public key")
	}
	if other.Value().IsOpIdentity() {
		return nil, errs.NewFailed("cannot add identity public key")
	}
	if !other.Value().IsTorsionFree() {
		return nil, errs.NewFailed("cannot add public key with torsion point")
	}
	return &PublicKey[P1, F1, P2, F2, E, S]{
		PublicKeyTrait: signatures.PublicKeyTrait[P1, S]{V: pk.Value().Add(other.Value())},
	}, nil
}

func NewPrivateKey[
	PK curves.PairingFriendlyPoint[PK, PKFE, Sig, SigFE, E, S], PKFE algebra.FieldElement[PKFE],
	Sig curves.PairingFriendlyPoint[Sig, SigFE, PK, PKFE, E, S], SigFE algebra.FieldElement[SigFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](subGroup curves.PairingFriendlyCurve[PK, PKFE, Sig, SigFE, E, S], v S) (*PrivateKey[PK, PKFE, Sig, SigFE, E, S], error) {
	if v.IsOpIdentity() {
		return nil, errs.NewFailed("cannot create private key from identity scalar")
	}
	publicKeyValue := subGroup.ScalarBaseMul(v)
	return &PrivateKey[PK, PKFE, Sig, SigFE, E, S]{
		PrivateKeyTrait: signatures.PrivateKeyTrait[PK, S]{
			V: v,
			PublicKeyTrait: signatures.PublicKeyTrait[PK, S]{
				V: publicKeyValue,
			},
		},
	}, nil
}

func NewPrivateKeyFromBytes[
	PK curves.PairingFriendlyPoint[PK, PKFE, Sig, SigFE, E, S], PKFE algebra.FieldElement[PKFE],
	Sig curves.PairingFriendlyPoint[Sig, SigFE, PK, PKFE, E, S], SigFE algebra.FieldElement[SigFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](subGroup curves.PairingFriendlyCurve[PK, PKFE, Sig, SigFE, E, S], input []byte) (*PrivateKey[PK, PKFE, Sig, SigFE, E, S], error) {
	sf := algebra.StructureMustBeAs[algebra.PrimeField[S]](subGroup.ScalarStructure())
	v, err := sf.FromBytes(input)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create private key from bytes")
	}
	return NewPrivateKey(subGroup, v)
}

type PrivateKey[
	PK curves.PairingFriendlyPoint[PK, PKFE, Sig, SigFE, E, S], PKFE algebra.FieldElement[PKFE],
	Sig curves.PairingFriendlyPoint[Sig, SigFE, PK, PKFE, E, S], SigFE algebra.FieldElement[SigFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
] struct {
	signatures.PrivateKeyTrait[PK, S]
}

func (sk *PrivateKey[PK, PKFE, Sig, SigFE, E, S]) Name() signatures.Name {
	return Name
}

func (sk *PrivateKey[PK, PKFE, Sig, SigFE, E, S]) Group() curves.Curve[PK, PKFE, S] {
	group, ok := sk.V.Structure().(curves.Curve[PK, PKFE, S])
	if !ok {
		panic(errs.NewType("private key value does not implement curves.Curve interface"))
	}
	return group
}

func (sk *PrivateKey[PK, PKFE, Sig, SigFE, E, S]) PublicKey() *PublicKey[PK, PKFE, Sig, SigFE, E, S] {
	return &PublicKey[PK, PKFE, Sig, SigFE, E, S]{PublicKeyTrait: sk.PublicKeyTrait}
}

func (sk *PrivateKey[PK, PKFE, Sig, SigFE, E, S]) Clone() *PrivateKey[PK, PKFE, Sig, SigFE, E, S] {
	if sk == nil {
		return nil
	}
	return &PrivateKey[PK, PKFE, Sig, SigFE, E, S]{PrivateKeyTrait: *sk.PrivateKeyTrait.Clone()}
}

func (sk *PrivateKey[PK, PKFE, Sig, SigFE, E, S]) Equal(other *PrivateKey[PK, PKFE, Sig, SigFE, E, S]) bool {
	if sk == nil || other == nil {
		return sk == other
	}
	return sk.PrivateKeyTrait.Equal(&other.PrivateKeyTrait)
}

func (sk *PrivateKey[PK, PKFE, Sig, SigFE, E, S]) Bytes() []byte {
	if sk == nil {
		return nil
	}
	return sliceutils.Reversed(sk.Value().Bytes())
}

func NewSignature[
	Sig curves.PairingFriendlyPoint[Sig, SigFE, PK, PKFE, E, S], SigFE algebra.FieldElement[SigFE],
	PK curves.PairingFriendlyPoint[PK, PKFE, Sig, SigFE, E, S], PKFE algebra.FieldElement[PKFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](v Sig, pop *ProofOfPossession[Sig, SigFE, PK, PKFE, E, S]) (*Signature[Sig, SigFE, PK, PKFE, E, S], error) {
	if v.IsOpIdentity() {
		return nil, errs.NewFailed("cannot create signature from identity point")
	}
	if !v.IsTorsionFree() {
		return nil, errs.NewFailed("cannot create signature from torsion point")
	}
	return &Signature[Sig, SigFE, PK, PKFE, E, S]{
		v:   v,
		pop: pop,
	}, nil
}

func NewSignatureFromBytes[
	Sig curves.PairingFriendlyPoint[Sig, SigFE, PK, PKFE, E, S], SigFE algebra.FieldElement[SigFE],
	PK curves.PairingFriendlyPoint[PK, PKFE, Sig, SigFE, E, S], PKFE algebra.FieldElement[PKFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](subGroup curves.PairingFriendlyCurve[Sig, SigFE, PK, PKFE, E, S], input []byte, pop *ProofOfPossession[Sig, SigFE, PK, PKFE, E, S]) (*Signature[Sig, SigFE, PK, PKFE, E, S], error) {
	if subGroup == nil {
		return nil, errs.NewIsNil("subgroup cannot be nil")
	}
	v, err := subGroup.FromBytes(input)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create signature from bytes")
	}
	return NewSignature(v, pop)
}

type Signature[
	Sig curves.PairingFriendlyPoint[Sig, SigFE, PK, PKFE, E, S], SigFE algebra.FieldElement[SigFE],
	PK curves.PairingFriendlyPoint[PK, PKFE, Sig, SigFE, E, S], PKFE algebra.FieldElement[PKFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
] struct {
	v   Sig
	pop *ProofOfPossession[Sig, SigFE, PK, PKFE, E, S]
}

func (sig *Signature[Sig, SigFE, PK, PKFE, E, S]) Value() Sig {
	return sig.v
}

func (sig *Signature[Sig, SigFE, PK, PKFE, E, S]) Bytes() []byte {
	return sig.v.ToCompressed()
}

func (sig *Signature[Sig, SigFE, PK, PKFE, E, S]) IsLong() bool {
	return !sig.v.InSourceGroup()
}

func (sig *Signature[Sig, SigFE, PK, PKFE, E, S]) Pop() *ProofOfPossession[Sig, SigFE, PK, PKFE, E, S] {
	if sig == nil {
		return nil
	}
	return sig.pop
}

func (sig *Signature[Sig, SigFE, PK, PKFE, E, S]) TryAdd(other *Signature[Sig, SigFE, PK, PKFE, E, S]) (*Signature[Sig, SigFE, PK, PKFE, E, S], error) {
	if other == nil {
		return nil, errs.NewIsNil("cannot add nil signature with proof of possession")
	}
	if other.v.IsOpIdentity() {
		return nil, errs.NewFailed("cannot add identity signature")
	}
	if !other.v.IsTorsionFree() {
		return nil, errs.NewFailed("cannot add signature with torsion point")
	}
	out := &Signature[Sig, SigFE, PK, PKFE, E, S]{v: sig.v.Add(other.v)}
	if sig.pop == nil && other.pop == nil {
		return out, nil
	}
	popAgg, err := sig.pop.TryAdd(other.pop)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not add proofs of possession in signature with proof of possession")
	}
	out.pop = popAgg
	return out, nil
}

func (sig *Signature[Sig, SigFE, PK, PKFE, E, S]) Equal(other *Signature[Sig, SigFE, PK, PKFE, E, S]) bool {
	return sig != nil && other != nil && sig.v.Equal(other.v) && sig.pop.Equal(other.pop)
}

func (sig *Signature[Sig, SigFE, PK, PKFE, E, S]) Clone() *Signature[Sig, SigFE, PK, PKFE, E, S] {
	return &Signature[Sig, SigFE, PK, PKFE, E, S]{
		v:   sig.v.Clone(),
		pop: sig.pop.Clone(),
	}
}

func (sig *Signature[Sig, SigFE, PK, PKFE, E, S]) HashCode() base.HashCode {
	return sig.v.HashCode()
}

func NewProofOfPossession[
	Sig curves.PairingFriendlyPoint[Sig, SigFE, PK, PKFE, E, S], SigFE algebra.FieldElement[SigFE],
	PK curves.PairingFriendlyPoint[PK, PKFE, Sig, SigFE, E, S], PKFE algebra.FieldElement[PKFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](v Sig) (*ProofOfPossession[Sig, SigFE, PK, PKFE, E, S], error) {
	if v.IsOpIdentity() {
		return nil, errs.NewFailed("cannot create proof of possession from identity signature")
	}
	if !v.IsTorsionFree() {
		return nil, errs.NewFailed("cannot create proof of possession from signature with torsion point")
	}
	sig, err := NewSignature(v, nil)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create proof of possession from signature")
	}
	return &ProofOfPossession[Sig, SigFE, PK, PKFE, E, S]{
		Signature: *sig,
	}, nil
}

func NewProofOfPossessionFromBytes[
	Sig curves.PairingFriendlyPoint[Sig, SigFE, PK, PKFE, E, S], SigFE algebra.FieldElement[SigFE],
	PK curves.PairingFriendlyPoint[PK, PKFE, Sig, SigFE, E, S], PKFE algebra.FieldElement[PKFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](subGroup curves.PairingFriendlyCurve[Sig, SigFE, PK, PKFE, E, S], input []byte) (*ProofOfPossession[Sig, SigFE, PK, PKFE, E, S], error) {
	if subGroup == nil {
		return nil, errs.NewIsNil("subgroup cannot be nil")
	}
	v, err := subGroup.FromBytes(input)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create proof of possession from bytes")
	}
	pop, err := NewProofOfPossession(v)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create proof of possession from signature")
	}
	return pop, nil
}

type ProofOfPossession[
	Sig curves.PairingFriendlyPoint[Sig, SigFE, PK, PKFE, E, S], SigFE algebra.FieldElement[SigFE],
	PK curves.PairingFriendlyPoint[PK, PKFE, Sig, SigFE, E, S], PKFE algebra.FieldElement[PKFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
] struct {
	Signature[Sig, SigFE, PK, PKFE, E, S]
}

func (pop *ProofOfPossession[Sig, SigFE, PK, PKFE, E, S]) Bytes() []byte {
	if pop == nil {
		return nil
	}
	return pop.Signature.Bytes()
}

func (pop *ProofOfPossession[Sig, SigFE, PK, PKFE, E, S]) Value() Sig {
	return pop.Signature.Value()
}

func (pop *ProofOfPossession[Sig, SigFE, PK, PKFE, E, S]) Equal(other *ProofOfPossession[Sig, SigFE, PK, PKFE, E, S]) bool {
	if pop == nil || other == nil {
		return pop == other
	}
	return pop.Signature.Equal(&other.Signature)
}

func (pop *ProofOfPossession[Sig, SigFE, PK, PKFE, E, S]) Clone() *ProofOfPossession[Sig, SigFE, PK, PKFE, E, S] {
	if pop == nil {
		return nil
	}
	return &ProofOfPossession[Sig, SigFE, PK, PKFE, E, S]{Signature: *pop.Signature.Clone()}
}

func (pop *ProofOfPossession[Sig, SigFE, PK, PKFE, E, S]) TryAdd(other *ProofOfPossession[Sig, SigFE, PK, PKFE, E, S]) (*ProofOfPossession[Sig, SigFE, PK, PKFE, E, S], error) {
	if other == nil {
		return nil, errs.NewIsNil("cannot add nil proof of possession")
	}
	v, err := pop.Signature.TryAdd(&other.Signature)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not add signatures in proof of possession")
	}
	return &ProofOfPossession[Sig, SigFE, PK, PKFE, E, S]{
		Signature: *v,
	}, nil
}

func (pop *ProofOfPossession[Sig, SigFE, PK, PKFE, E, S]) HashCode() base.HashCode {
	return pop.Signature.HashCode()
}

func AggregateAll[
	PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, ET, S], PKFE algebra.FieldElement[PKFE],
	SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, ET, S], SGFE algebra.FieldElement[SGFE],
	ET algebra.MultiplicativeGroupElement[ET], S algebra.PrimeFieldElement[S],
	Xs ~[]X, X interface {
		TryAdd(other X) (X, error)
	},
](xs Xs) (X, error) {
	if len(xs) == 0 {
		return *new(X), errs.NewFailed("cannot aggregate empty slice of elements")
	}
	result, err := iterutils.ReduceOrError(
		slices.Values(xs[1:]),
		xs[0],
		func(acc X, pk X) (X, error) {
			aggregated, err := acc.TryAdd(pk)
			if err != nil {
				return *new(X), errs.WrapFailed(err, "could not aggregate public keys")
			}
			return aggregated, nil
		})
	if err != nil {
		return *new(X), errs.WrapFailed(err, "failed to aggregate BLS elements")
	}
	return result, nil
}

func _[
	PK curves.PairingFriendlyPoint[PK, PKFE, Sig, SigFE, E, S], PKFE algebra.FieldElement[PKFE],
	Sig curves.PairingFriendlyPoint[Sig, SigFE, PK, PKFE, E, S], SigFE algebra.FieldElement[SigFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
]() {
	var (
		_ signatures.AggregatablePublicKey[*PublicKey[PK, PKFE, Sig, SigFE, E, S]]                      = (*PublicKey[PK, PKFE, Sig, SigFE, E, S])(nil)
		_ signatures.PrivateKey[*PrivateKey[PK, PKFE, Sig, SigFE, E, S]]                                = (*PrivateKey[PK, PKFE, Sig, SigFE, E, S])(nil)
		_ signatures.IncrementallyAggregatableSignature[*Signature[PK, PKFE, Sig, SigFE, E, S]]         = (*Signature[PK, PKFE, Sig, SigFE, E, S])(nil)
		_ signatures.IncrementallyAggregatableSignature[*ProofOfPossession[PK, PKFE, Sig, SigFE, E, S]] = (*ProofOfPossession[PK, PKFE, Sig, SigFE, E, S])(nil)
	)
}
