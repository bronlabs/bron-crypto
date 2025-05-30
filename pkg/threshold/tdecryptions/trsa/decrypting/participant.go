package decrypting

import (
	"crypto"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/threshold/trsa"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/trsa/signing"
)

type Codecryptor struct {
	Cosigner *signing.Cosigner
}

func NewCodecryptor(authKey types.AuthKey, shard *trsa.Shard, protocol types.ThresholdProtocol, quorum ds.Set[types.IdentityKey], h crypto.Hash) (*Codecryptor, error) {
	cosigner, err := signing.NewCosigner(authKey, shard, protocol, quorum, h)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create cosigner")
	}

	return &Codecryptor{Cosigner: cosigner}, nil
}
