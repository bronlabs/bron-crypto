package elgamal

// import (
// 	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
// 	"github.com/bronlabs/bron-crypto/pkg/base/algebra/constructions"
// 	"github.com/bronlabs/bron-crypto/pkg/base/errs"
// 	"github.com/bronlabs/bron-crypto/pkg/encryption"
// )

// const Name encryption.Name = "elgamal"

// type UnderlyingGroup[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]] interface {
// 	algebra.FiniteAbelianGroup[E, S]
// 	algebra.CyclicSemiGroup[E]
// }

// type UnderlyingGroupElement[E interface {
// 	algebra.FiniteAbelianGroupElement[E, S]
// 	algebra.CyclicSemiGroupElement[E]
// }, S algebra.UintLike[S]] interface {
// 	algebra.FiniteAbelianGroupElement[E, S]
// 	algebra.CyclicSemiGroupElement[E]
// }

// type CiphertextSpace[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]] = constructions.FiniteDirectSumModule[UnderlyingGroup[E, S], E, S]

// func NewScheme[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]](g UnderlyingGroup[E, S], z algebra.ZnLike[S]) (*Scheme[E, S], error) {
// 	if g == nil {
// 		return nil, errs.NewIsNil("group")
// 	}
// 	if z == nil {
// 		return nil, errs.NewIsNil("z")
// 	}
// 	ctSpace, err := NewCiphertextSpace(g)
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "failed to create ciphertext space")
// 	}
// 	return &Scheme[E, S]{g, z, ctSpace}, nil
// }

// type Scheme[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]] struct {
// 	g       UnderlyingGroup[E, S]
// 	z       algebra.ZnLike[S]
// 	ctSpace *CiphertextSpace[E, S]
// }

// func (*Scheme[E, S]) Name() encryption.Name {
// 	return Name
// }

// func (s *Scheme[E, S]) Group() UnderlyingGroup[E, S] {
// 	if s == nil {
// 		return nil
// 	}
// 	return s.g
// }

// func (s *Scheme[E, S]) ScalarField() algebra.ZnLike[S] {
// 	if s == nil {
// 		return nil
// 	}
// 	return s.z
// }

// func (s *Scheme[E, S]) CiphertextSpace() *CiphertextSpace[E, S] {
// 	if s == nil {
// 		return nil
// 	}
// 	return s.ctSpace
// }

// func (s *Scheme[E, S]) Keygen(opts ...KeyGeneratorOption[E, S]) (*KeyGenerator[E, S], error) {
// 	kg := &KeyGenerator[E, S]{s.g, s.z}
// 	for _, opt := range opts {
// 		if err := opt(kg); err != nil {
// 			return nil, errs.WrapFailed(err, "key generator option failed")
// 		}
// 	}
// 	return kg, nil
// }

// func (s *Scheme[E, S]) Encrypter(opts ...EncrypterOption[E, S]) (*Encrypter[E, S], error) {
// 	enc := &Encrypter[E, S]{s.g, s.z, s.ctSpace}
// 	for _, opt := range opts {
// 		if err := opt(enc); err != nil {
// 			return nil, errs.WrapFailed(err, "encrypter option failed")
// 		}
// 	}
// 	return enc, nil
// }

// func (s *Scheme[E, S]) Decrypter(sk *PrivateKey[E, S], opts ...DecrypterOption[E, S]) (*Decrypter[E, S], error) {
// 	out := &Decrypter[E, S]{sk}
// 	for _, opt := range opts {
// 		if err := opt(out); err != nil {
// 			return nil, errs.WrapFailed(err, "decrypter option failed")
// 		}
// 	}
// 	return out, nil
// }

// func NewCiphertextSpace[E UnderlyingGroupElement[E, S], S algebra.UintLike[S]](g UnderlyingGroup[E, S]) (*CiphertextSpace[E, S], error) {
// 	if g == nil {
// 		return nil, errs.NewIsNil("group")
// 	}
// 	out, err := constructions.NewFiniteDirectSumModule(g, 2)
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "failed to create ciphertext space")
// 	}
// 	return out, nil
// }

// // func _[
// // 	E UnderlyingGroupElement[E, S], S algebra.UintLike[S],
// // ]() {
// // 	var (
// // 		_ encryption.Scheme[
// // 			*PrivateKey[E, S], *PublicKey[E, S], *Plaintext[E, S], *Ciphertext[E, S], *Nonce[E, S],
// // 			*KeyGenerator[E, S], *Encrypter[E, S], *Decrypter[E, S],
// // 		] = (*Scheme[E, S])(nil)

// // 		_ encryption.HomomorphicScheme[
// // 			*PrivateKey[E, S], *PublicKey[E, S],
// // 			*Plaintext[E, S], E,
// // 			*Ciphertext[E, S], *constructions.FiniteDirectSumModuleElement[UnderlyingGroup[E, S], E, S],
// // 			*Nonce[E, S], S,
// // 			*KeyGenerator[E, S], *Encrypter[E, S], *Decrypter[E, S],
// // 		] = (*Scheme[E, S])(nil)
// // 	)
// // }
