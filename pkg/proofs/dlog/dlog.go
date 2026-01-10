package dlog

import (
	"strings"

	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

// Type is the identifier for proofs of knowledge of discrete logarithm.
const Type = "-dlog_pok-"

// IsProvingKnowledgeOfDiscreteLog checks whether the given sigma proof indicates
// that it is a proof of knowledge of discrete logarithm.
func IsProvingKnowledgeOfDiscreteLog(name sigma.Name) bool {
	return name != "" && strings.Contains(string(name), Type)
}
