package newprzs

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

type Key [2 * base.ComputationalSecurityBytes]byte

func Deal(n, t int, prng io.Reader) ([]map[int]Key, error) {
	shares := make(map[int]Key)
	subSets := newSubSetsSet(n, n-t)
	for _, subSet := range subSets {
		var key Key
		_, err := io.ReadFull(prng, key[:])
		if err != nil {
			return nil, errs.WrapRandomSampleFailed(err, "cannot sample random")
		}
		shares[subSet] = key
	}

	seeds := make([]map[int]Key, n)
	for p := 0; p < n; p++ {
		seeds[p] = make(map[int]Key)
		for _, subSet := range subSets {
			if subSetContains(subSet, p) {
				seeds[p][subSet] = shares[subSet]
			}
		}
	}

	return seeds, nil
}
