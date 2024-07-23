package signing

import (
	"github.com/cronokirby/saferith"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/rsa"
)

type RsaPartialSignature struct {
	Share *saferith.Nat
}

func Aggregate(pk *rsa.PublicKey, padding rsa.Padding, protocol types.ThresholdSignatureProtocol, message []byte, partialSignatures ds.Map[types.IdentityKey, *RsaPartialSignature]) (*saferith.Nat, error) {
	delta := int64(1)
	for i := int64(2); i <= int64(protocol.TotalParties()); i++ {
		delta *= i
	}

	digestPaddedNat, err := padding.HashAndPad(pk.N.BitLen(), protocol.SigningSuite().Hash(), message)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot pad message")
	}

	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	lambdaJ := make([]int64, partialSignatures.Size())
	sJ := make([]*RsaPartialSignature, partialSignatures.Size())
	for idx, idJ := range partialSignatures.Keys() {
		var ok bool
		sJ[idx], ok = partialSignatures.Get(idJ)
		if !ok {
			return nil, errs.NewFailed("invalid identities")
		}
		lambda := delta
		j, ok := sharingConfig.Reverse().Get(idJ)
		if !ok {
			return nil, errs.NewFailed("invalid identities")
		}
		for _, idI := range partialSignatures.Keys() {
			if idI.Equal(idJ) {
				continue
			}
			i, ok := sharingConfig.Reverse().Get(idI)
			if !ok {
				return nil, errs.NewFailed("invalid identities")
			}
			lambda *= int64(i)
			lambda /= int64(i) - int64(j)
		}
		lambdaJ[idx] = lambda
	}

	w := new(saferith.Nat).SetUint64(1)
	for i := range sJ {
		xjExp := 2 * lambdaJ[i]
		var wj *saferith.Nat
		if xjExp < 0 {
			base := new(saferith.Nat).ModInverse(sJ[i].Share, pk.N)
			exp := new(saferith.Nat).SetUint64(uint64(-xjExp))
			wj = new(saferith.Nat).Exp(base, exp, pk.N)
		} else {
			base := sJ[i].Share
			exp := new(saferith.Nat).SetUint64(uint64(xjExp))
			wj = new(saferith.Nat).Exp(base, exp, pk.N)
		}
		w = new(saferith.Nat).ModMul(w, wj, pk.N)
	}

	x := 4 * delta * delta * delta * delta * delta
	y := int64(pk.E)
	a, b, g := extendedGCD(x, y)
	if g != 1 {
		return nil, errs.NewFailed("invalid parameters")
	}

	var wToA *saferith.Nat
	var mToB *saferith.Nat
	if a < 0 {
		minusANat := new(saferith.Nat).SetUint64(uint64(-a))
		wInv := new(saferith.Nat).ModInverse(w, pk.N)
		wToA = new(saferith.Nat).Exp(wInv, minusANat, pk.N)
	} else {
		aNat := new(saferith.Nat).SetUint64(uint64(a))
		wToA = new(saferith.Nat).Exp(w, aNat, pk.N)
	}
	if b < 0 {
		minusBNat := new(saferith.Nat).SetUint64(uint64(-b))
		mInv := new(saferith.Nat).ModInverse(digestPaddedNat, pk.N)
		mToB = new(saferith.Nat).Exp(mInv, minusBNat, pk.N)
	} else {
		bNat := new(saferith.Nat).SetUint64(uint64(b))
		mToB = new(saferith.Nat).Exp(digestPaddedNat, bNat, pk.N)
	}

	sig := new(saferith.Nat).ModMul(wToA, mToB, pk.N)
	verifyMessage := new(saferith.Nat).Exp(sig, new(saferith.Nat).SetUint64(pk.E), pk.N)
	if digestPaddedNat.Eq(verifyMessage) != 1 {
		return nil, errs.NewFailed("invalid signature")
	}

	return sig, nil
}

func extendedGCD(a, b int64) (x, y, gcd int64) {
	oldS, s := int64(1), int64(0)
	oldR, r := a, b

	for r != 0 {
		q := oldR / r
		oldR, r = r, oldR-q*r
		oldS, s = s, oldS-q*s
	}
	t := (oldR - oldS*a) / b

	return oldS, t, oldR
}
