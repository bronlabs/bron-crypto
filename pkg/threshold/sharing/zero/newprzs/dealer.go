package newprzs

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

func Deal(n, t int, field curves.ScalarField, prng io.Reader) ([]map[int]curves.Scalar, error) {
	shares := make(map[int]curves.Scalar)
	subSets := newSubSetsSet(n, n-t)
	for _, subSet := range subSets {
		var err error
		shares[subSet], err = field.Random(prng)
		if err != nil {
			return nil, errs.WrapRandomSampleFailed(err, "cannot sample random")
		}
	}

	seeds := make([]map[int]curves.Scalar, n)
	for p := 0; p < n; p++ {
		seeds[p] = make(map[int]curves.Scalar)
		for _, subSet := range subSets {
			if subSetContains(subSet, p) {
				seeds[p][subSet] = shares[subSet]
			}
		}
	}

	return seeds, nil
}
