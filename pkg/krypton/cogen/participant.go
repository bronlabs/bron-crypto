package cogen

import (
	"math/big"
	"sort"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
)

var _ integration.Participant = (*Participant)(nil)

type Participant struct {
	myAuthKey           integration.AuthKey
	round               int
	signingMessage      []byte
	otherGroups         map[types.IdentityHash]integration.IdentityKey
	newCogenIdentityKey func(curves.Point) (integration.IdentityKey, error)

	_ types.Incomparable
}

func (p *Participant) GetAuthKey() integration.AuthKey {
	return p.myAuthKey
}

func (p *Participant) GetSharingId() int {
	return -1
}

func (p *Participant) GetCohortConfig() *integration.CohortConfig {
	return nil
}

func NewParticipant(newCogenAuthKey func() (integration.AuthKey, error), newCogenIdentityKey func(curves.Point) (integration.IdentityKey, error)) (*Participant, error) {
	authKey, err := newCogenAuthKey()
	if err != nil {
		return nil, errs.WrapFailed(err, "could not generate auth key")
	}
	return &Participant{
		round:               1,
		myAuthKey:           authKey,
		newCogenIdentityKey: newCogenIdentityKey,
	}, nil
}

type CohortCertificateMessage struct {
	Groups []curves.Point
}

func (c *CohortCertificateMessage) Len() int {
	return len(c.Groups)
}

func (c *CohortCertificateMessage) Less(i, j int) bool {
	iBytes := c.Groups[i].ToAffineCompressed()
	jBytes := c.Groups[j].ToAffineCompressed()
	return big.NewInt(0).SetBytes(iBytes).Cmp(big.NewInt(0).SetBytes(jBytes)) < 0
}

func (c *CohortCertificateMessage) Swap(i, j int) {
	c.Groups[i], c.Groups[j] = c.Groups[j], c.Groups[i]
}
func (c *CohortCertificateMessage) Encode() []byte {
	var result []byte
	sort.Sort(c)
	for _, group := range c.Groups {
		result = append(result, group.ToAffineCompressed()...)
	}
	return result
}
