package blummod

import (
	"crypto/sha3"
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/ioutils"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

func groupElementsBytes(elems []*znstar.RSAGroupElementUnknownOrder) [][]byte {
	out := make([][]byte, len(elems))
	for i, elem := range elems {
		if elem != nil {
			out[i] = elem.Bytes()
		}
	}
	return out
}

func rsaGroupFromStatement(statement *Statement) (*znstar.RSAGroupUnknownOrder, error) {
	if statement == nil || statement.X == nil || statement.X.Group() == nil || statement.X.Group().N() == nil {
		return nil, ErrInvalidArgument.WithMessage("statement is nil")
	}
	group, err := znstar.NewRSAGroupOfUnknownOrder(statement.X.Group().N())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create RSA group")
	}
	return group, nil
}

func rsaGroupFromWitness(witness *Witness) (*znstar.RSAGroupKnownOrder, error) {
	if witness == nil || witness.W == nil || witness.W.Group() == nil {
		return nil, ErrInvalidArgument.WithMessage("witness is nil")
	}
	arith := witness.W.Arithmetic().CrtModN
	p, err := num.NPlus().FromNatCT(arith.Params.PNat)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot convert p")
	}
	q, err := num.NPlus().FromNatCT(arith.Params.QNat)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot convert q")
	}
	group, err := znstar.NewRSAGroup(p, q)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create RSA group")
	}
	return group, nil
}

func validatePublicModulus(n *num.NatPlus) error {
	if n == nil || n.IsOne() {
		return ErrVerificationFailed.WithMessage("verification failed")
	}
	if n.IsEven() {
		return ErrVerificationFailed.WithMessage("verification failed")
	}
	if n.IsProbablyPrime() {
		return ErrVerificationFailed.WithMessage("verification failed")
	}
	return nil
}

func validateResponseShape(response *Response, group *znstar.RSAGroupUnknownOrder) error {
	if len(response.X) != M || len(response.Z) != M || len(response.A) != M || len(response.B) != M {
		return ErrVerificationFailed.WithMessage("verification failed")
	}
	for i := range M {
		if response.A[i] > 1 || response.B[i] > 1 {
			return ErrVerificationFailed.WithMessage("verification failed")
		}
		if !elementInGroup(response.X[i], group) || !elementInGroup(response.Z[i], group) {
			return ErrVerificationFailed.WithMessage("verification failed")
		}
	}
	return nil
}

func elementInGroup(elem *znstar.RSAGroupElementUnknownOrder, group *znstar.RSAGroupUnknownOrder) bool {
	return elem != nil && group != nil && elem.IsUnknownOrder() && elem.Modulus().Equal(group.Modulus())
}

func deriveChallengeElements(statement *Statement, challenge sigma.ChallengeBytes) ([]*znstar.RSAGroupElementUnknownOrder, error) {
	if len(challenge) != challengeBytesLength {
		return nil, ErrInvalidArgument.WithMessage("invalid challenge length")
	}
	group, err := rsaGroupFromStatement(statement)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	xof, err := challengeXOF(group, challenge)
	if err != nil {
		return nil, errs.Wrap(err)
	}

	ys := make([]*znstar.RSAGroupElementUnknownOrder, M)
	for i := range M {
		ys[i], err = readChallengeElement(group, xof)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot hash challenge to group")
		}
	}
	return ys, nil
}

func challengeXOF(group *znstar.RSAGroupUnknownOrder, challenge sigma.ChallengeBytes) (*sha3.SHAKE, error) {
	xof := sha3.NewCSHAKE256(nil, []byte(challengeHashLabel))
	if _, err := ioutils.WriteLengthPrefixed(xof,
		group.Modulus().BytesBE(),
		[]byte(challenge),
	); err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot absorb challenge seed")
	}
	return xof, nil
}

func readChallengeElement(group *znstar.RSAGroupUnknownOrder, xof io.Reader) (*znstar.RSAGroupElementUnknownOrder, error) {
	digest := make([]byte, group.WideElementSize())
	for {
		if _, err := io.ReadFull(xof, digest); err != nil {
			return nil, errs.Wrap(err)
		}

		var x, v numct.Nat
		if ok := x.SetBytes(digest); ok == ct.False {
			return nil, ErrFailed.WithMessage("cannot interpret hash digest")
		}
		group.ModulusCT().Mod(&v, &x)
		if v.Coprime(group.Modulus().Value()) != ct.True {
			continue
		}

		out, err := group.FromNatCT(&v)
		if err != nil {
			return nil, errs.Wrap(err)
		}
		return out, nil
	}
}

func minusOneKnown(group *znstar.RSAGroupKnownOrder) (*znstar.RSAGroupElementKnownOrder, error) {
	m := minusOneNat(group.Modulus())
	elem, err := group.FromNatCT(m)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return elem, nil
}

func minusOneUnknown(group *znstar.RSAGroupUnknownOrder) (*znstar.RSAGroupElementUnknownOrder, error) {
	m := minusOneNat(group.Modulus())
	elem, err := group.FromNatCT(m)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return elem, nil
}

func minusOneNat(modulus *num.NatPlus) *numct.Nat {
	out := modulus.Value().Clone()
	out.Decrement()
	return out
}

func nInverseModPhi(sk *paillier.PrivateKey) (*num.Nat, error) {
	arith := sk.Arithmetic().CrtModN
	var inv numct.Nat
	if ok := arith.Phi.ModInv(&inv, arith.N.Nat()); ok == ct.False {
		return nil, ErrFailed.WithMessage("cannot invert N modulo phi(N)")
	}
	out, err := num.N().FromNatCT(&inv)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return out, nil
}

func fourthRootExponent(sk *paillier.PrivateKey) (*num.Nat, error) {
	phi := sk.Arithmetic().CrtModN.Phi.Nat()
	var phiPlusFour numct.Nat
	phiPlusFour.Add(phi, numct.NewNat(4))

	var sqrtExp numct.Nat
	sqrtExp.Rsh(&phiPlusFour, 3)

	var fourthRootExp numct.Nat
	fourthRootExp.Mul(&sqrtExp, &sqrtExp)

	out, err := num.N().FromNatCT(&fourthRootExp)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return out, nil
}

func isThreeModFour(n *numct.Nat) bool {
	if n == nil {
		return false
	}
	return n.Bit(0) == 1 && n.Bit(1) == 1
}
