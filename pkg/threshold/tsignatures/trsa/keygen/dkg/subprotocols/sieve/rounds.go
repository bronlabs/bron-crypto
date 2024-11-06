package sieve

import (
	crand "crypto/rand"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/replicated"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/trsa/keygen/dkg/subprotocols/mul_two"
	"math/big"
)

func (p *Participant) Round1() (p2pOut network.RoundMessages[types.ThresholdProtocol, *Round1P2P]) {
	primeBitLen := p.PrimeDealer.GetBitLen()

	primeLowBound := new(big.Int)
	primeLowBound.SetBit(primeLowBound, int(primeBitLen-1), 1)
	primeLowBound.SetBit(primeLowBound, int(primeBitLen-2), 1)
	primeShareLowBound := new(big.Int).Div(new(big.Int).Add(primeLowBound, big.NewInt(int64(p.Protocol.TotalParties()-1))), big.NewInt(int64(p.Protocol.TotalParties())))
	primeHighBound := new(big.Int)
	primeHighBound.SetBit(primeHighBound, int(primeBitLen), 1)
	primeShareHighBound := new(big.Int).Div(primeHighBound, big.NewInt(int64(p.Protocol.TotalParties())))
	primeShareRange := new(big.Int).Sub(primeShareHighBound, primeShareLowBound)

	pShare, err := crand.Int(p.Prng, primeShareRange)
	if err != nil {
		panic(err)
	}
	pShare.Add(pShare, primeShareLowBound)
	qShare, err := crand.Int(p.Prng, primeShareRange)
	if err != nil {
		panic(err)
	}
	qShare.Add(qShare, primeShareLowBound)

	if p.MySharingId == 1 {
		pShare.SetBit(pShare, 0, 1)
		pShare.SetBit(pShare, 1, 1)
		qShare.SetBit(qShare, 0, 1)
		qShare.SetBit(qShare, 1, 1)
	} else {
		pShare.SetBit(pShare, 0, 0)
		pShare.SetBit(pShare, 1, 0)
		qShare.SetBit(qShare, 0, 0)
		qShare.SetBit(qShare, 1, 0)
	}

	pShares, err := p.PrimeDealer.Share(pShare, p.Prng)
	if err != nil {
		panic(err)
	}
	qShares, err := p.PrimeDealer.Share(qShare, p.Prng)
	if err != nil {
		panic(err)
	}

	p2pOut = network.NewRoundMessages[types.ThresholdProtocol, *Round1P2P]()
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			p.State.pShare = pShares[sharingId]
			p.State.qShare = qShares[sharingId]
		} else {
			p2pOut.Put(id, &Round1P2P{
				PShare: pShares[sharingId],
				QShare: qShares[sharingId],
			})
		}
	}

	return p2pOut
}

func (p *Participant) Round2(p2pIn network.RoundMessages[types.ThresholdProtocol, *Round1P2P]) (p2pOut network.RoundMessages[types.ThresholdProtocol, *Round2P2P]) {
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		in, _ := p2pIn.Get(id)
		p.State.pShare = p.State.pShare.Add(in.PShare)
		p.State.qShare = p.State.qShare.Add(in.QShare)
	}

	p.State.pqMul = mul_two.NewParticipant(p.MyIdentityKey, p.Protocol, p.Prng, replicated.BitLen(2*p.PrimeDealer.GetBitLen()))
	pqMulRound1 := p.State.pqMul.Round1(p.State.pShare, p.State.qShare)

	p2pOut = network.NewRoundMessages[types.ThresholdProtocol, *Round2P2P]()
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}

		mqMulR1, _ := pqMulRound1.Get(id)
		p2pOut.Put(id, &Round2P2P{MulPQR1: mqMulR1})
	}

	return p2pOut
}

func (p *Participant) Round3(p2pIn network.RoundMessages[types.ThresholdProtocol, *Round2P2P]) *Round3Broadcast {
	pqMulRound1 := network.NewRoundMessages[types.ThresholdProtocol, *mul_two.Round1P2P]()
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		in, _ := p2pIn.Get(id)
		pqMulRound1.Put(id, in.MulPQR1)
	}

	p.State.nShare = p.State.pqMul.Round2(pqMulRound1)
	out := &Round3Broadcast{NShare: p.State.nShare}

	return out
}

func (p *Participant) Round4(bIn network.RoundMessages[types.ThresholdProtocol, *Round3Broadcast]) (pShare, qShare *replicated.IntShare, n *big.Int, ok bool) {
	nShares := []*replicated.IntShare{p.State.nShare}
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}

		in, _ := bIn.Get(id)
		nShares = append(nShares, in.NShare)
	}

	n, err := p.PrimeDealer.Reveal(nShares...)
	if err != nil {
		panic(err)
	}

	gcdCheck := new(big.Int).GCD(nil, nil, n, ParamMB)
	if gcdCheck.Cmp(big.NewInt(1)) > 0 {
		return p.State.pShare, p.State.qShare, n, false
	}

	return p.State.pShare, p.State.qShare, n, true
}
