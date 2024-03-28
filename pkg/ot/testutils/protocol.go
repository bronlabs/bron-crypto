package testutils

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/ot"
)

type BaseOtProtocol struct {
	types.Protocol

	l  int
	xi int
}

func NewProtocol(baseProtocol types.Protocol, Xi, L int) ot.Protocol {
	return &BaseOtProtocol{
		Protocol: baseProtocol,
		l:        L,
		xi:       Xi,
	}
}

func (p *BaseOtProtocol) L() int {
	return p.l
}

func (p *BaseOtProtocol) Xi() int {
	return p.xi
}
