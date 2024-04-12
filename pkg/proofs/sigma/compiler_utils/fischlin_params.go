package compiler_utils

import (
	"github.com/copperexchange/krypton-primitives/pkg/proofs/dleq/chaum"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/dlog/batch_schnorr"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/dlog/schnorr"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/paillier/nthroot"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma"
)

const defaultRho = uint64(16)

// chosen experimentally
var simplifiedFischlinRho = map[sigma.Name]uint64{
	schnorr.Name:       16, // b = 8, t = 13
	chaum.Name:         16, // b = 8, t = 13
	nthroot.Name:       32, // b = 4, t = 11
	batch_schnorr.Name: 32, // b = 4, t = 11
}

// TODO: At some point move it to specific sigma protocol
func getSimplifiedFischlinRho(sigmaName sigma.Name) uint64 {
	v, ok := simplifiedFischlinRho[sigmaName]
	if ok {
		return v
	} else {
		return defaultRho
	}
}
