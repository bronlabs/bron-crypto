package replicated

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

type IntDealer struct {
	threshold   uint
	total       uint
	bitLen      uint
	modulus     *big.Int
	specialForm bool
}

type SharingOpt func(dealer *IntDealer) error

func BitLen(bitLen uint) SharingOpt {
	return func(dealer *IntDealer) error {
		if dealer.modulus != nil {
			return errs.NewFailed("either bit length or modulus can be supplied")
		}
		if bitLen < 1 {
			return errs.NewFailed("bit length cannot be zero")
		}
		dealer.bitLen = bitLen
		return nil
	}
}

func Modulus(modulus *big.Int) SharingOpt {
	return func(dealer *IntDealer) error {
		if dealer.bitLen != 0 {
			return errs.NewFailed("either bit length or modulus can be supplied")
		}
		dealer.modulus = modulus
		return nil
	}
}

func SpecialForm(specialForm bool) SharingOpt {
	return func(dealer *IntDealer) error {
		dealer.specialForm = specialForm
		return nil
	}
}

func NewIntDealer(threshold, total uint, opts ...SharingOpt) (*IntDealer, error) {
	if total < 2 || threshold < 2 || threshold >= total {
		return nil, errs.NewFailed("invalid access structure")
	}

	d := &IntDealer{threshold: threshold, total: total}
	for _, opt := range opts {
		if err := opt(d); err != nil {
			return nil, errs.WrapFailed(err, "failed to initialize dealer")
		}
	}
	if d.modulus == nil && d.bitLen == 0 {
		return nil, errs.NewFailed("modulus or bit length must be supplied")
	}

	return d, nil
}

func (d *IntDealer) GetModulus() *big.Int {
	return d.modulus
}

func (d *IntDealer) GetBitLen() uint {
	return d.bitLen
}

func (d *IntDealer) Share(secret *big.Int, prng io.Reader) (map[types.SharingID]*IntShare, error) {
	maxUnqualifiedSets, err := BuildSortedMaxUnqualifiedSets(d.threshold, d.total)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot build max unqualified sets")
	}

	subShares := make([]*big.Int, len(maxUnqualifiedSets))
	subShares[0] = new(big.Int).Set(secret)
	if d.modulus != nil {
		subShares[0].Mod(subShares[0], d.modulus)
	}

	for i := 1; i < len(maxUnqualifiedSets); i++ {
		subShareBitLen := uint(0)
		if d.modulus != nil {
			subShareBitLen = uint(d.modulus.BitLen()) * 2 // to minimize bias
		} else {
			subShareBitLen = d.bitLen + base.ComputationalSecurity
		}

		subShareBytes := make([]byte, (subShareBitLen+7)/8)
		_, err := io.ReadFull(prng, subShareBytes)
		if err != nil {
			return nil, errs.WrapRandomSample(err, "cannot sample subshare bytes")
		}
		subShare := new(big.Int).SetBytes(subShareBytes)

		if d.modulus == nil {
			neg := make([]byte, 1)
			_, err = io.ReadFull(prng, neg)
			if err != nil {
				return nil, errs.WrapRandomSample(err, "cannot sample subshare bytes")
			}
			if (neg[0] & 1) != 0 {
				subShare.Neg(subShare)
			}
		} else {
			subShare.Mod(subShare, d.modulus)
		}

		if d.specialForm {
			subShare.SetBit(subShare, 0, 0)
			subShare.SetBit(subShare, 1, 0)
		}

		subShares[i] = subShare
		subShares[0] = new(big.Int).Sub(subShares[0], subShare)
		if d.modulus != nil {
			subShares[0].Mod(subShares[0], d.modulus)
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

func (d *IntDealer) Reveal(shares ...*IntShare) (*big.Int, error) {
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
	if d.modulus != nil {
		secret = secret.Mod(secret, d.modulus)
	}

	return secret, nil
}
