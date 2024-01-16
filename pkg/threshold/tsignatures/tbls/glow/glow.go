package glow

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/dleq/chaum"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/bls"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/boldyreva02"
)

const TranscriptLabel = "COPPER_KRYPTON_THRESHOLD_BLS_GLOW-"

type Participant interface {
	integration.Participant

	IsSignatureAggregator() bool
}

type KeySubGroup = bls12381.G1
type SignatureSubGroup = bls12381.G2

type SigningKeyShare = boldyreva02.SigningKeyShare[KeySubGroup]
type PublicKeyShares = boldyreva02.PublicKeyShares[KeySubGroup]
type Shard = boldyreva02.Shard[KeySubGroup]

type PartialSignature struct {
	SigmaI    *bls.Signature[SignatureSubGroup]
	DleqProof *chaum.Proof
}
