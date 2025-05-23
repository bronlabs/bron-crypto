package signing

import (
	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/numutils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/rep23"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/trsa"
)

func Aggregate(publicShard *trsa.PublicShard, partialSignatures ...*trsa.PartialSignature) (*saferith.Nat, error) {
	dealer1 := rep23.NewIntExpScheme(publicShard.N1)
	s1Shares := sliceutils.Map(partialSignatures, func(s *trsa.PartialSignature) *rep23.IntExpShare { return s.S1Share })
	s1, err := dealer1.Open(s1Shares...)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot open s1 shares")
	}

	dealer2 := rep23.NewIntExpScheme(publicShard.N2)
	s2Shares := sliceutils.Map(partialSignatures, func(s *trsa.PartialSignature) *rep23.IntExpShare { return s.S2Share })
	s2, err := dealer2.Open(s2Shares...)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot open s1 shares")
	}

	s := numutils.Crt(s1, s2, publicShard.N1, publicShard.N2.Nat())
	return s, nil
}
