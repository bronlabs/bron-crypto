package glow

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler"
	fiatShamir "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler/fiatshamir"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/bls"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/boldyreva02"
)

const (
	transcriptLabel  = "COPPER_KRYPTON_TBLS_GLOW-"
	DleqNIZKCompiler = fiatShamir.Name
)

type KeySubGroup = bls12381.G1
type SignatureSubGroup = bls12381.G2

type SigningKeyShare = boldyreva02.SigningKeyShare[KeySubGroup]
type PublicKeyShares = boldyreva02.PartialPublicKeys[KeySubGroup]
type Shard = boldyreva02.Shard[KeySubGroup]

var NewShard = boldyreva02.NewShard[KeySubGroup]

type PartialSignature struct {
	SigmaI    *bls.Signature[SignatureSubGroup]
	DleqProof compiler.NIZKPoKProof
	SessionId []byte // Required for the DLEQ verification if the aggregator is not a cosigner

	_ ds.Incomparable
}

func (ps *PartialSignature) Validate(protocol types.ThresholdProtocol) error {
	if ps.SigmaI == nil {
		return errs.NewIsNil("sigma_i")
	}
	if ps.SigmaI.Value.IsAdditiveIdentity() {
		return errs.NewIsIdentity("sigma_i is identity")
	}
	if ps.DleqProof == nil {
		return errs.NewIsNil("dleq proof")
	}
	return nil
}
