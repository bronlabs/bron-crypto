package trsa

import (
	nativeRsa "crypto/rsa"
	"hash"
	"math/big"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/rsa"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/replicated"
)

type Shard struct {
	nativeRsa.PublicKey
	PShare *replicated.IntShare
	QShare *replicated.IntShare
	DShare *replicated.IntShare
}

type PartialSignature struct {
	S map[replicated.SharingIdSet]*big.Int
}

func (s *Shard) SignPartially(padding rsa.Padding, hashFunc func() hash.Hash, message []byte) (*PartialSignature, error) {
	partSignature := &PartialSignature{
		S: make(map[replicated.SharingIdSet]*big.Int),
	}

	paddedDigest, err := padding.HashAndPad(s.N.BitLen(), hashFunc, message)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot pad message")
	}
	for sharingIdSet, subShareValue := range s.DShare.SubShares {
		partSignature.S[sharingIdSet] = new(big.Int).Exp(paddedDigest, subShareValue, s.N)
	}

	return partSignature, nil
}

func Aggregate(pk *nativeRsa.PublicKey, partialSignatures ...*PartialSignature) ([]byte, error) {
	aggregatedSignatures := make(map[replicated.SharingIdSet]*big.Int)
	for _, partialSignature := range partialSignatures {
		for sharingIdSet, partialSignatureValue := range partialSignature.S {
			if _, ok := aggregatedSignatures[sharingIdSet]; !ok {
				aggregatedSignatures[sharingIdSet] = partialSignatureValue
			} else if partialSignatureValue.Cmp(aggregatedSignatures[sharingIdSet]) != 0 {
				return nil, errs.NewFailed("invalid partial signature")
			}
		}
	}

	signatureInt := big.NewInt(1)
	for _, s := range aggregatedSignatures {
		signatureInt.Mul(signatureInt, s)
		signatureInt.Mod(signatureInt, pk.N)
	}

	signature := make([]byte, len(pk.N.Bytes()))
	signatureInt.FillBytes(signature)
	return signature, nil
}
