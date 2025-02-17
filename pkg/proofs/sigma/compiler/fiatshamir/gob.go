package fiatshamir

import (
	"encoding/gob"
	"sync"

	"github.com/bronlabs/krypton-primitives/pkg/proofs/dleq/chaum"
	"github.com/bronlabs/krypton-primitives/pkg/proofs/dlog/batch_schnorr"
	"github.com/bronlabs/krypton-primitives/pkg/proofs/dlog/schnorr"
	"github.com/bronlabs/krypton-primitives/pkg/proofs/paillier/nthroots"
	"github.com/bronlabs/krypton-primitives/pkg/proofs/paillier/range"
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
		gob.Register(new(Proof[paillierrange.Commitment, paillierrange.Response]))
	})
}
