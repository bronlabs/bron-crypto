package keygen

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/mpc"
	mpcbls "github.com/bronlabs/bron-crypto/pkg/mpc/meta/signatures/bls"
	"github.com/bronlabs/bron-crypto/pkg/mpc/meta/signatures/bls/boldyreva02"
	"github.com/bronlabs/errs-go/errs"
)

var ErrIsNil = errs.New("input is nil")

func NewShortKeyShard[
	PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, E, S], PKFE algebra.PrimeFieldElement[PKFE],
	SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, E, S], SGFE algebra.FieldElement[SGFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](
	output *mpc.BaseShard[PK, S],
) (*boldyreva02.Shard[PK, PKFE, SG, SGFE, E, S], error) {
	if output == nil {
		return nil, ErrIsNil.WithMessage("output is nil")
	}
	shard, err := mpcbls.NewShortKeyShard(output.Share(), output.VerificationVector(), output.MSP())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create tBLS short key shard")
	}
	return shard, nil
}

func NewLongKeyShard[
	PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, E, S], PKFE algebra.FieldElement[PKFE],
	SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, E, S], SGFE algebra.PrimeFieldElement[SGFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](
	output *mpc.BaseShard[PK, S],
) (*boldyreva02.Shard[PK, PKFE, SG, SGFE, E, S], error) {
	if output == nil {
		return nil, ErrIsNil.WithMessage("output is nil")
	}
	shard, err := mpcbls.NewLongKeyShard(output.Share(), output.VerificationVector(), output.MSP())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create tBLS long key shard")
	}
	return shard, nil
}
