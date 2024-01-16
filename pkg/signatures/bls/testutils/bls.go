package testutils

import (
	crand "crypto/rand"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/bls"
)

type (
	G1 = bls12381.G1
	G2 = bls12381.G2
)

func keygenInG1() (*bls.PrivateKey[G1], error) {
	privateKey, err := bls.KeyGen[G1](crand.Reader)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not generate key")
	}
	if privateKey.D().IsZero() {
		return nil, errs.NewIsNil("privateKey.D() is zeri")
	}
	return privateKey, nil
}

func keygenInG2() (*bls.PrivateKey[G2], error) {
	privateKey, err := bls.KeyGen[G2](crand.Reader)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not generate key")
	}
	if privateKey.D().IsZero() {
		return nil, errs.NewIsNil("privateKey.D() is zeri")
	}
	return privateKey, nil
}

func RoundTripWithKeysInG1(message []byte, scheme bls.RogueKeyPrevention) (*bls.PrivateKey[G1], *bls.Signature[G2], *bls.ProofOfPossession[G2], error) {
	privateKey, err := keygenInG1()
	if err != nil {
		return nil, nil, nil, errs.WrapFailed(err, "could not generate key")
	}
	signer, err := bls.NewSigner[G1, G2](privateKey, scheme)
	if err != nil {
		return nil, nil, nil, errs.WrapFailed(err, "could not create signer")
	}

	signature, pop, err := signer.Sign(message, nil)
	if err != nil {
		return nil, nil, nil, errs.WrapFailed(err, "could not sign")
	}
	if scheme == bls.POP {
		if pop == nil {
			return nil, nil, nil, errs.NewIsNil("pop is nil")
		}
		if pop.Value.IsIdentity() {
			return nil, nil, nil, errs.NewIsNil("pop is identity")
		}
		if !pop.Value.IsTorsionElement(bls12381.NewG2().SubGroupOrder()) {
			return nil, nil, nil, errs.NewIsNil("pop is torsion free")
		}
		err = bls.PopVerify(privateKey.PublicKey, pop)
		if err != nil {
			return nil, nil, nil, errs.WrapFailed(err, "could not verify pop")
		}
	} else if pop != nil {
		return nil, nil, nil, errs.NewIsNil("pop is not nil")
	}
	if signature == nil {
		return nil, nil, nil, errs.NewIsNil("signature is nil")
	}
	if signature.Value.IsIdentity() {
		return nil, nil, nil, errs.NewIsNil("signature is identity")
	}
	if !signature.Value.IsTorsionElement(bls12381.NewG2().SubGroupOrder()) {
		return nil, nil, nil, errs.NewIsNil("signature is torsion free")
	}

	err = bls.Verify(privateKey.PublicKey, signature, message, pop, scheme, nil)
	if err != nil {
		return nil, nil, nil, errs.WrapFailed(err, "could not verify signature")
	}
	return privateKey, signature, pop, nil
}

func RoundTripWithKeysInG2(message []byte, scheme bls.RogueKeyPrevention) (*bls.PrivateKey[G2], *bls.Signature[G1], *bls.ProofOfPossession[G1], error) {
	privateKey, err := keygenInG2()
	if err != nil {
		return nil, nil, nil, errs.WrapFailed(err, "could not generate key")
	}
	signer, err := bls.NewSigner[G2, G1](privateKey, scheme)
	if err != nil {
		return nil, nil, nil, errs.WrapFailed(err, "could not create signer")
	}

	signature, pop, err := signer.Sign(message, nil)
	if err != nil {
		return nil, nil, nil, errs.WrapFailed(err, "could not sign")
	}
	if scheme == bls.POP {
		if pop == nil {
			return nil, nil, nil, errs.NewIsNil("pop is nil")
		}
		if pop.Value.IsIdentity() {
			return nil, nil, nil, errs.NewIsNil("pop is identity")
		}
		if !pop.Value.IsTorsionElement(bls12381.NewG1().SubGroupOrder()) {
			return nil, nil, nil, errs.NewIsNil("pop is not torsion free")
		}
		err = bls.PopVerify(privateKey.PublicKey, pop)
		if err != nil {
			return nil, nil, nil, errs.WrapFailed(err, "could not verify pop")
		}
	} else if pop != nil {
		return nil, nil, nil, errs.NewIsNil("pop is not nil")
	}
	if signature == nil {
		return nil, nil, nil, errs.NewIsNil("signature is nil")
	}
	if signature.Value.IsIdentity() {
		return nil, nil, nil, errs.NewIsNil("signature is identity")
	}
	if !signature.Value.IsTorsionElement(bls12381.NewG1().SubGroupOrder()) {
		return nil, nil, nil, errs.NewIsNil("signature is torsion free")
	}

	err = bls.Verify(privateKey.PublicKey, signature, message, pop, scheme, nil)
	if err != nil {
		return nil, nil, nil, errs.WrapFailed(err, "could not verify signature")
	}
	return privateKey, signature, pop, nil
}
