package dlog

import (
	"strings"

	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

const Type = "-dlog_pok-"

func IsProvingKnowledgeOfDiscreteLog(name sigma.Name) bool {
	return name != "" && strings.Contains(string(name), Type)
}
