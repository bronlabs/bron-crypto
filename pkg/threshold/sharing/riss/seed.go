package riss

import (
	crand "crypto/rand"
	"io"
	"maps"
	"math/big"
	"math/bits"
	"slices"

	"github.com/copperexchange/krypton-primitives/pkg/base/combinatorics"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

type PseudoRandomSeed struct {
	Prfs map[SharingIdSet]io.Reader
}

func (s *PseudoRandomSeed) ThresholdAccessStructure() (t, n uint) {
	t = uint(slices.Collect(maps.Keys(s.Prfs))[0].Size() + 1)

	union := SharingIdSet(0)
	for sharingIdSet := range s.Prfs {
		union |= sharingIdSet
	}
	n = uint(bits.OnesCount64(uint64(union)) + 1)

	return t, n
}

func (s *PseudoRandomSeed) Sample(opts ...SharingOpt) (share *IntShare, err error) {
	options := NewPseudoRandomSharingOpts(opts...)
	threshold, total := s.ThresholdAccessStructure()
	subSharesCount, err := combinatorics.BinomialCoefficient(total, threshold-1)
	if err != nil {
		return nil, errs.WrapValidation(err, "cannot compute binomial coefficient")
	}

	var low, high *big.Int
	if options.GetModulus() != nil {
		low = big.NewInt(0)
		high = new(big.Int).Set(options.GetModulus())
	} else if options.GetBitLen() != 0 {
		low = new(big.Int)
		low.SetBit(low, int(options.GetBitLen())-1, 1)
		low.Add(low, big.NewInt(int64(subSharesCount-1)))
		low.Div(low, big.NewInt(int64(subSharesCount)))
		high = new(big.Int)
		high.SetBit(high, int(options.GetBitLen()), 1)
		high.Add(high, big.NewInt(int64(subSharesCount-1)))
		high.Div(high, big.NewInt(int64(subSharesCount)))
	} else if l, h := options.GetRange(); l != nil && h != nil {
		low = new(big.Int).Set(l)
		high = new(big.Int).Set(h)
		low.Add(low, big.NewInt(int64(subSharesCount-1)))
		low.Div(low, big.NewInt(int64(subSharesCount)))
		high.Add(high, big.NewInt(int64(subSharesCount-1)))
		high.Div(high, big.NewInt(int64(subSharesCount)))
	} else {
		return nil, errs.NewValidation("no range provided")
	}
	rangeBound := new(big.Int).Sub(high, low)

	share = &IntShare{
		SubShares: make(map[SharingIdSet]*big.Int),
	}
	for sharingIdSet, prf := range s.Prfs {
		share.SubShares[sharingIdSet], err = crand.Int(prf, rangeBound)
		if err != nil {
			return nil, errs.WrapRandomSample(err, "cannot generate random share")
		}
		share.SubShares[sharingIdSet].Add(share.SubShares[sharingIdSet], low)
	}
	return share, nil
}
