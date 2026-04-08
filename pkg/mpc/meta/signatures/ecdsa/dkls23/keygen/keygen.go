package keygen

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/mpc"
	"github.com/bronlabs/bron-crypto/pkg/mpc/meta/signatures/ecdsa/dkls23"
	"github.com/bronlabs/errs-go/errs"
)

// NewShard creates a DKLs23 shard from the base shard.
func NewShard[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](baseShard *mpc.BaseShard[P, S]) (*dkls23.Shard[P, B, S], error) {
	shard, err := dkls23.NewShard(baseShard)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create DKLs23 shard")
	}
	return shard, nil
}
