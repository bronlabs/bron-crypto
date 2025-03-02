package paillier

import (
	"github.com/cronokirby/saferith"
	"golang.org/x/sync/errgroup"

	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/base/modular"
	"github.com/bronlabs/krypton-primitives/pkg/base/utils/numutils"
	"github.com/bronlabs/krypton-primitives/pkg/indcpa"
)

var (
	_ indcpa.HomomorphicDecryptionKey[*PlainText, *Nonce, *CipherText, *Scalar, *PublicKey] = (*SecretKey)(nil)
)

func (sk *SecretKey) NonceMul(lhs *Nonce, rhs *Scalar) (nonce *Nonce, err error) {
	if !sk.validNonce(lhs) {
		return nil, errs.NewValidation("invalid nonce")
	}
	if !sk.validScalar(rhs) {
		return nil, errs.NewValidation("invalid nonce")
	}

	ep := rhs.Mod(sk.pm1)
	eq := rhs.Mod(sk.qm1)

	var rp, rq *saferith.Nat
	var eg errgroup.Group
	eg.Go(func() error {
		var err error
		rp, err = modular.FastExp(lhs, ep, sk.P)
		return err //nolint:wrapcheck // checked in eg.Wait()
	})
	eg.Go(func() error {
		var err error
		rq, err = modular.FastExp(lhs, eq, sk.Q)
		return err //nolint:wrapcheck // checked in eg.Wait()
	})
	err = eg.Wait()
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to multiply nonce")
	}

	nonce = numutils.CrtWithPrecomputation(rp, rq, sk.P, sk.Q.Nat(), sk.qInv)
	return nonce, nil
}

func (sk *SecretKey) CipherTextMul(lhs *CipherText, rhs *Scalar) (cipherText *CipherText, err error) {
	if !sk.validCiphertext(lhs) {
		return nil, errs.NewValidation("invalid ciphertext")
	}
	if !sk.validScalar(rhs) {
		return nil, errs.NewValidation("invalid scalar")
	}

	sp := rhs.Mod(sk.phiPP)
	sq := rhs.Mod(sk.phiQQ)

	var cp, cq *saferith.Nat
	var eg errgroup.Group
	eg.Go(func() error {
		var err error
		cp, err = modular.FastExp(&lhs.C, sp, sk.pp)
		return err //nolint:wrapcheck // checked in eg.Wait()
	})
	eg.Go(func() error {
		var err error
		cq, err = modular.FastExp(&lhs.C, sq, sk.qq)
		return err //nolint:wrapcheck // checked in eg.Wait()
	})
	err = eg.Wait()
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to multiply ciphertext")
	}

	c := numutils.CrtWithPrecomputation(cp, cq, sk.pp, sk.qq.Nat(), sk.qqInv)
	cipherText = new(CipherText)
	cipherText.C.SetNat(c)
	return cipherText, nil
}
