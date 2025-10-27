package fischlin

import (
	"github.com/bronlabs/bron-crypto/pkg/proofs/dlog/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/proofs/paillier/nthroots"
	paillierrange "github.com/bronlabs/bron-crypto/pkg/proofs/paillier/range"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

const (
	defaultRho = uint64(16)
)

func getRho[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response](sigmaProtocol sigma.Protocol[X, W, A, S, Z]) uint64 {
	switch sigmaProtocol.Name() {
	case schnorr.Name:
		return 16
	case nthroots.Name:
		return 32
	case paillierrange.Name:
		return 16
	default:
		return defaultRho
	}
}
