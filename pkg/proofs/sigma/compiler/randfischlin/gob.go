package randfischlin

import (
	"encoding/gob"
	"sync"

	"github.com/copperexchange/krypton-primitives/pkg/proofs/dleq/chaum"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/dlog/batch_schnorr"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/dlog/schnorr"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/paillier/nthroots"
)

var (
	registerOnce sync.Once
)

func RegisterForGob() {
	registerOnce.Do(func() {
		gob.Register(new(Proof[schnorr.Commitment, schnorr.Response]))
		gob.Register(new(Proof[batch_schnorr.Commitment, batch_schnorr.Response]))
		gob.Register(new(Proof[*chaum.Commitment, chaum.Response]))
		gob.Register(new(Proof[nthroots.Commitment, nthroots.Response]))
	})
}
