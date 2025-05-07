package fiatshamir

import (
	"encoding/gob"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/bronlabs/bron-crypto/pkg/proofs/dlog/schnorr"
	"sync"
	//"github.com/bronlabs/bron-crypto/pkg/proofs/dleq/chaum"
	//"github.com/bronlabs/bron-crypto/pkg/proofs/dlog/batch_schnorr"
	//"github.com/bronlabs/bron-crypto/pkg/proofs/dlog/schnorr"
	//"github.com/bronlabs/bron-crypto/pkg/proofs/paillier/nthroots"
	//"github.com/bronlabs/bron-crypto/pkg/proofs/paillier/range"
)

var (
	registerOnce sync.Once
)

func RegisterForGob() {
	registerOnce.Do(func() {
		gob.Register(new(Proof[*schnorr.Commitment[*k256.Point, *k256.BaseFieldElement, *k256.Scalar], *schnorr.Response[*k256.Scalar]]))
		gob.Register(new(Proof[*schnorr.Commitment[*p256.Point, *p256.BaseFieldElement, *p256.Scalar], *schnorr.Response[*p256.Scalar]]))
		gob.Register(new(Proof[*schnorr.Commitment[*edwards25519.Point, *edwards25519.BaseFieldElement, *edwards25519.Scalar], *schnorr.Response[*edwards25519.Scalar]]))
		gob.Register(new(Proof[*schnorr.Commitment[*pasta.PallasPoint, *pasta.PallasBaseFieldElement, *pasta.PallasScalar], *schnorr.Response[*pasta.PallasScalar]]))
		gob.Register(new(Proof[*schnorr.Commitment[*pasta.VestaPoint, *pasta.VestaBaseFieldElement, *pasta.VestaScalar], *schnorr.Response[*pasta.VestaScalar]]))
		gob.Register(new(Proof[*schnorr.Commitment[*bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.Scalar], *schnorr.Response[*bls12381.Scalar]]))
		gob.Register(new(Proof[*schnorr.Commitment[*bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.Scalar], *schnorr.Response[*bls12381.Scalar]]))
	})
}
