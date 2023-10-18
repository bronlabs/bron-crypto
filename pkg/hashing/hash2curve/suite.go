package hash2curve

import (
	"strings"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
)

const ID_SEPARATOR = "_"

// Suite implements a Hash-to-Curve suite following https://datatracker.ietf.org/doc/html/rfc9380#section-8
type Suite struct {
	Id     string
	hasher Hasher
	curve  curves.Curve
}

func (suite *Suite) GenerateSuiteId() {
	var sb strings.Builder
	// CURVE_ID: a human-readable representation of the target elliptic curve.
	sb.WriteString(suite.curve.Name())
	sb.WriteString(ID_SEPARATOR)
	// HASH_ID: a human-readable representation of the expand_message function and any underlying hash primitives used in hash_to_field
	sb.WriteString(suite.hasher.Name())
}
