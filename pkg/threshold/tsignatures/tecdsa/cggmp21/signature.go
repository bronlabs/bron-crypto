package cggmp21

import (
	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/signatures/ecdsa"
)

type PartialSignature struct {
	V *int
	R curves.Scalar
	S curves.Scalar
}

func Aggregate(partialSignatures ...*PartialSignature) (*ecdsa.Signature, error) {
	if len(partialSignatures) < 2 {
		return nil, errs.NewFailed("not enough partial signatures")
	}
	v := partialSignatures[0].V
	r := partialSignatures[0].R
	s := partialSignatures[0].S
	for i := 1; i < len(partialSignatures); i++ {
		if v == nil {
			if partialSignatures[i].V != v {
				return nil, errs.NewFailed("partial signatures do not match")
			}
		} else {
			if *v != *partialSignatures[i].V {
				return nil, errs.NewFailed("partial signatures do not match")
			}
		}
		if !partialSignatures[i].R.Equal(r) {
			return nil, errs.NewFailed("partial signatures do not match")
		}
		s = s.Add(partialSignatures[i].S)
	}

	return &ecdsa.Signature{
		V: v,
		R: r,
		S: s,
	}, nil
}
