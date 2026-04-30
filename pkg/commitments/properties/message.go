package properties

import (
	"testing"

	serdeprop "github.com/bronlabs/bron-crypto/pkg/base/serde/properties"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"pgregory.net/rapid"
)

type MessageGenerator[M commitments.Message] = rapid.Generator[M]

type MessageProperties[M commitments.Message] struct {
	MessageGenerator *MessageGenerator[M]

	MessagesAreEqual func(M, M) bool
}

func (p *MessageProperties[M]) CheckAll(t *testing.T) {
	t.Parallel()
	t.Run("IsCBORSerialisable", p.IsCBORSerialisable)
}

func (p *MessageProperties[M]) IsCBORSerialisable(t *testing.T) {
	serialisationSuite := serdeprop.SerialisationProperties[M]{
		Generator: p.MessageGenerator,
		AreEqual:  p.MessagesAreEqual,
	}
	serialisationSuite.CheckAll(t)
}
