package properties

import (
	"testing"

	serdeprop "github.com/bronlabs/bron-crypto/pkg/base/serde/testutils/properties"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
	"pgregory.net/rapid"
)

type NonceGenerator[N encryption.Nonce] = rapid.Generator[N]

type NonceProperties[N encryption.Nonce] struct {
	NonceGenerator *NonceGenerator[N]
	NoncesAreEqual func(N, N) bool
}

func (n *NonceProperties[N]) CheckAll(t *testing.T) {
	t.Parallel()
	t.Run("IsCBORSerialisable", n.IsCBORSerialisable)
}

func (n *NonceProperties[N]) IsCBORSerialisable(t *testing.T) {
	serialisationSuite := serdeprop.SerialisationProperties[N]{
		Generator: n.NonceGenerator,
		AreEqual:  n.NoncesAreEqual,
	}
	serialisationSuite.CheckAll(t)
}
