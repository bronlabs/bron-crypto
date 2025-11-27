package teddsa

import (
	nativeEdward25519 "crypto/ed25519"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/binrep3"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tschnorr"
)

type AuxiliaryInfo struct {
	seedShare [4]*binrep3.Share `cbor:"seedShare"`
}

func NewAuxiliaryInfo(seedShare [4]*binrep3.Share) *AuxiliaryInfo {
	return &AuxiliaryInfo{seedShare: seedShare}
}

func (ai *AuxiliaryInfo) SeedShare() [4]*binrep3.Share {
	return ai.seedShare
}

type Shard struct {
	tschnorr.Shard[*edwards25519.PrimeSubGroupPoint, *edwards25519.Scalar]
	AuxiliaryInfo
}

func (s *Shard) NativeEdDSAPublicKey() nativeEdward25519.PublicKey {
	return s.PublicKey().Value().ToCompressed()
}
