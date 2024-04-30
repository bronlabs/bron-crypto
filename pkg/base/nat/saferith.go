//go:build !boringnat

// if no boringnat build flag is provided, this would be the default implementation

package nat

import "github.com/copperexchange/krypton-primitives/pkg/base/nat/internal/saferith"

var BigNats Nats = &saferith.SNats{}
