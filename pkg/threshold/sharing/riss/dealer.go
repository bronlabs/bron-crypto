package riss

import (
	"io"
	"maps"
	"math/big"
	"slices"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/combinatorics"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils/itertools"
)

type Dealer struct {
	threshold uint
	total     uint
	options   SharingOpts
}

func NewDealer(threshold, total uint, opts ...SharingOpt) (*Dealer, error) {
	if total < 2 || threshold < 2 || (threshold-1)*2 >= total {
		return nil, errs.NewValidation("invalid access structure")
	}

	d := &Dealer{
		threshold: threshold,
		total:     total,
		options:   NewSharingOpts(opts...),
	}
	if d.options.GetModulus() == nil && d.options.GetBitLen() == 0 {
		return nil, errs.NewValidation("no bound or modulus provided")
	}
	if d.options.GetModulus() != nil && d.options.GetBitLen() > 0 {
		return nil, errs.NewValidation("both bound or modulus provided")
	}

	return d, nil
}

func (d *Dealer) Share(secret *big.Int, prng io.Reader) (map[types.SharingID]*IntShare, error) {
	maxUnqualifiedSets, err := BuildSortedMaxUnqualifiedSets(d.threshold, d.total)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot build max unqualified sets")
	}

	subShares := make([]*big.Int, len(maxUnqualifiedSets))
	subShares[0] = new(big.Int).Set(secret)
	if d.options.GetModulus() != nil {
		subShares[0].Mod(subShares[0], d.options.GetModulus())
	}

	for i := 1; i < len(maxUnqualifiedSets); i++ {
		var subShareBitLen uint
		if d.options.GetModulus() != nil {
			subShareBitLen = uint(d.options.GetModulus().BitLen()) * 2 // to minimise bias
		} else {
			subShareBitLen = d.options.GetBitLen() + base.ComputationalSecurity
		}

		subShareBytes := make([]byte, (subShareBitLen+7)/8)
		_, err := io.ReadFull(prng, subShareBytes)
		if err != nil {
			return nil, errs.WrapRandomSample(err, "cannot sample subshare bytes")
		}
		subShare := new(big.Int).SetBytes(subShareBytes)

		if d.options.GetModulus() == nil {
			neg := make([]byte, 1)
			_, err = io.ReadFull(prng, neg)
			if err != nil {
				return nil, errs.WrapRandomSample(err, "cannot sample subshare bytes")
			}
			if (neg[0] & 1) != 0 {
				subShare.Neg(subShare)
			}
		} else {
			subShare.Mod(subShare, d.options.GetModulus())
		}

		if d.options.IsSpecialForm() {
			subShare.SetBit(subShare, 0, 0)
			subShare.SetBit(subShare, 1, 0)
		}

		subShares[i] = subShare
		subShares[0] = new(big.Int).Sub(subShares[0], subShare)
		if d.options.GetModulus() != nil {
			subShares[0].Mod(subShares[0], d.options.GetModulus())
		}
	}

	shares := make(map[types.SharingID]*IntShare)
	for i := range d.total {
		sharingId := types.SharingID(i + 1)
		share := &IntShare{
			SubShares: make(map[SharingIdSet]*big.Int),
		}
		for j, maxUnqualifiedSet := range maxUnqualifiedSets {
			if !maxUnqualifiedSet.Has(sharingId) {
				share.SubShares[maxUnqualifiedSet] = subShares[j]
			}
		}
		shares[sharingId] = share
	}

	return shares, nil
}

func (d *Dealer) Open(shares ...*IntShare) (*big.Int, error) {
	subShares := make(map[SharingIdSet]*big.Int)
	for _, share := range shares {
		shareT, shareN := share.ThresholdAccessStructure()
		if shareT != d.threshold || shareN != d.total {
			return nil, errs.NewFailed("consistency check fail")
		}

		for sharingIdSet, subShareValue := range share.SubShares {
			if _, ok := subShares[sharingIdSet]; !ok {
				subShares[sharingIdSet] = subShareValue
			} else if subShares[sharingIdSet].Cmp(subShareValue) != 0 {
				return nil, errs.NewFailed("consistency check fail")
			}
		}
	}

	expectedSubSharesLen, err := combinatorics.BinomialCoefficient(d.total, d.threshold-1)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot compute binomial coefficient")
	}
	if len(subShares) != int(expectedSubSharesLen) {
		return nil, errs.NewFailed("consistency check fail")
	}

	secret := itertools.Fold(func(acc, x *big.Int) *big.Int { return new(big.Int).Add(acc, x) }, big.NewInt(0), slices.Collect(maps.Values(subShares))...)
	if d.options.GetModulus() != nil {
		secret.Mod(secret, d.options.GetModulus())
	}

	return secret, nil
}
