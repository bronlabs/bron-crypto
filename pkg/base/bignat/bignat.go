package bignat

import (
	//saferithImpl "github.com/copperexchange/krypton-primitives/pkg/base/bignat/internal/saferith/nats"
	bigNumImpl "github.com/copperexchange/krypton-primitives/pkg/base/bignat/internal/bignum/nats"
	"github.com/copperexchange/krypton-primitives/pkg/base/bignat/nats"
)

var Nats nats.Nats = bigNumImpl.NewNats()
