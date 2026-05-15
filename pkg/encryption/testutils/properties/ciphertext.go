package properties

import (
	"testing"

	serdeprop "github.com/bronlabs/bron-crypto/pkg/base/serde/testutils/properties"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
	"pgregory.net/rapid"
)

type CiphertextGenerator[C encryption.Ciphertext[C]] = rapid.Generator[C]

type CiphertextProperties[C encryption.Ciphertext[C]] struct {
	CiphertextGenerator *CiphertextGenerator[C]
	CiphertextsAreEqual func(C, C) bool
}

func (c *CiphertextProperties[C]) CheckAll(t *testing.T) {
	t.Parallel()
	t.Run("IsCBORSerialisable", c.IsCBORSerialisable)
}

func (c *CiphertextProperties[C]) IsCBORSerialisable(t *testing.T) {
	serialisationSuite := serdeprop.SerialisationProperties[C]{
		Generator: c.CiphertextGenerator,
		AreEqual:  c.CiphertextsAreEqual,
	}
	serialisationSuite.CheckAll(t)
}
