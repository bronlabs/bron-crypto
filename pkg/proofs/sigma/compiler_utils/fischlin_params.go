package compilerUtils

import (
	//"github.com/bronlabs/bron-crypto/pkg/proofs/dleq/chaum"
	//"github.com/bronlabs/bron-crypto/pkg/proofs/dlog/batch_schnorr".
	"github.com/bronlabs/bron-crypto/pkg/proofs/dlog/schnorr"
	//"github.com/bronlabs/bron-crypto/pkg/proofs/paillier/nthroots"
	//"github.com/bronlabs/bron-crypto/pkg/proofs/paillier/range".
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

const defaultRho = uint64(16)

// chosen experimentally
var simplifiedFischlinRho = map[sigma.Name]uint64{
	schnorr.Name: 16, // b = 8, t = 13
	//chaum.Name:         16, // b = 8, t = 13
	//nthroots.Name:      32, // b = 4, t = 11
	//batch_schnorr.Name: 32, // b = 4, t = 11
	//paillierrange.Name: 16,
}

// TODO: At some point move it to specific sigma protocol
func getFischlinRho(sigmaName sigma.Name) uint64 {
	v, ok := simplifiedFischlinRho[sigmaName]
	if ok {
		return v
	} else {
		return defaultRho
	}
}
