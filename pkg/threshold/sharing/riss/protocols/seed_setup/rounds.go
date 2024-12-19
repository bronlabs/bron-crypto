package riss_seed_setup

import (
	crand "crypto/rand"
	"crypto/subtle"
	"io"
	randv2 "math/rand/v2"

	"golang.org/x/crypto/blake2b"

	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/riss"
)

func (p *Participant) Round1() (p2pOut network.RoundMessages[types.ThresholdProtocol, *Round1P2P]) {
	p.State.Seeds = make(map[riss.SharingIdSet][64]byte)

	for _, sharingIdSet := range p.MaxUnqualifiedSets {
		if sharingIdSet.Has(p.MySharingId) {
			continue
		}
		var seed [64]byte
		_, _ = io.ReadFull(crand.Reader, seed[:])
		p.State.Seeds[sharingIdSet] = seed
	}

	p2pOut = network.NewRoundMessages[types.ThresholdProtocol, *Round1P2P]()
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		out := &Round1P2P{
			Seeds: make(map[riss.SharingIdSet][64]byte),
		}
		for sharingIdSet, seed := range p.State.Seeds {
			if !sharingIdSet.Has(sharingId) {
				out.Seeds[sharingIdSet] = seed
			}
		}
		p2pOut.Put(id, out)
	}

	return p2pOut
}

func (p *Participant) Round2(p2pIn network.RoundMessages[types.ThresholdProtocol, *Round1P2P]) (prssSeed *riss.PseudoRandomSeed) {
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		in, _ := p2pIn.Get(id)
		for sharingIdSet, seed := range p.State.Seeds {
			if sharingIdSet.Has(sharingId) {
				continue
			}
			var dst [64]byte
			inSeed := in.Seeds[sharingIdSet]
			subtle.XORBytes(dst[:], seed[:], inSeed[:])
			p.State.Seeds[sharingIdSet] = dst
		}
	}

	prssSeed = &riss.PseudoRandomSeed{
		Prfs: make(map[riss.SharingIdSet]io.Reader),
	}
	for sharingIdSet, seed := range p.State.Seeds {
		prssSeed.Prfs[sharingIdSet] = randv2.NewChaCha8(blake2b.Sum256(seed[:]))
	}

	return prssSeed
}
