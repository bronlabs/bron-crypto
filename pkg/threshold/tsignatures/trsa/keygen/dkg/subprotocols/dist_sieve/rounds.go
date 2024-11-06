package dist_sieve

import (
	"cmp"
	crand "crypto/rand"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/replicated"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/trsa/keygen/dkg/subprotocols/mul_n"
	"maps"
	"math/big"
	"slices"
)

func (p *Participant) Round1() (p2pOut network.RoundMessages[types.ThresholdProtocol, *Round1P2P]) {
	var a *big.Int
	for {
		var err error
		a, err = crand.Int(p.Prng, p.MB)
		if err != nil {
			panic(err)
		}
		a.SetBit(a, 0, 1)
		if new(big.Int).GCD(nil, nil, a, p.MB).Cmp(big.NewInt(1)) == 0 {
			break
		}
	}

	dealer, err := replicated.NewIntDealer(p.Protocol.Threshold(), p.Protocol.TotalParties(), replicated.Modulus(p.MB))
	if err != nil {
		panic(err)
	}
	aShares, err := dealer.Share(a, p.Prng)
	if err != nil {
		panic(err)
	}

	p.State.aShares = make(map[types.SharingID]*replicated.IntShare)
	p2pOut = network.NewRoundMessages[types.ThresholdProtocol, *Round1P2P]()
	for sharingId, identityKey := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			p.State.aShares[sharingId] = aShares[sharingId]
		} else {
			p2pOut.Put(identityKey, &Round1P2P{AShare: aShares[sharingId]})
		}
	}

	return p2pOut
}

func (p *Participant) Round2(p2pIn network.RoundMessages[types.ThresholdProtocol, *Round1P2P]) (p2pOut network.RoundMessages[types.ThresholdProtocol, *Round2P2P]) {
	for sharingId, identityKey := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		in, _ := p2pIn.Get(identityKey)
		p.State.aShares[sharingId] = in.AShare
	}

	aShares := valuesSortedByKeys(p.State.aShares)
	p.State.aMul = mul_n.NewParticipant(p.MyIdentityKey, p.Protocol, p.Prng, replicated.Modulus(p.MB))
	mulR1 := p.State.aMul.Round1(aShares...)

	return mulR1
}

func (p *Participant) Round3R(p2pIn network.RoundMessages[types.ThresholdProtocol, *Round2P2P]) (p2pOutR2 network.RoundMessages[types.ThresholdProtocol, *Round2P2P], bOutR3 *Round3Broadcast) {
	mulRn, bShare := p.State.aMul.Round2R(p2pIn)
	if bShare == nil {
		return mulRn, nil
	}

	p.State.aModFour = 0
	for _, set := range p.ExpTable[p.MySharingId] {
		p.State.aModFour += (bShare.SubShares[set].Bit(1) << 1) + bShare.SubShares[set].Bit(0)
		p.State.aModFour %= 4
	}

	p.State.bShare = bShare
	return nil, &Round3Broadcast{AModFour: p.State.aModFour}
}

func (p *Participant) Round4(bIn network.RoundMessages[types.ThresholdProtocol, *Round3Broadcast]) *Round4Broadcast {
	for sharingId, identityKey := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		in, _ := bIn.Get(identityKey)
		p.State.aModFour += in.AModFour
		p.State.aModFour %= 4
	}

	lowBound := new(big.Int)
	lowBound.SetBit(lowBound, int(p.PrimeBitLen)-1, 1)
	lowBound.SetBit(lowBound, int(p.PrimeBitLen)-2, 1)
	lowBound.SetBit(lowBound, 1, 1)
	lowBound.SetBit(lowBound, 0, 1)
	lowBound.Add(lowBound, p.MB)
	lowBound.Sub(lowBound, big.NewInt(1))
	lowBound.Div(lowBound, p.MB)

	highBound := new(big.Int)
	highBound.SetBit(highBound, int(p.PrimeBitLen), 1)
	highBound.Div(highBound, p.MB)
	boundRange := new(big.Int).Sub(highBound, lowBound)

	var r *big.Int
	for {
		rBytes, err := p.Tape.ExtractBytes("r", (uint(boundRange.BitLen())+7)/8)
		if err != nil {
			panic(err)
		}
		r = new(big.Int).SetBytes(rBytes)
		r.Add(r, lowBound)
		r.SetBit(r, 0, 1-(p.State.aModFour>>1))
		if r.Cmp(highBound) < 0 {
			break
		}
	}
	p.State.pShare = p.State.bShare.AddValue(new(big.Int).Mul(p.MB, r))

	adjust := uint(0)
	for set, value := range p.State.pShare.SubShares {
		if set != replicated.SharingIdSet((1<<(p.Protocol.Threshold()-1))-1) {
			k := (value.Bit(1) << 1) + value.Bit(0)
			p.State.pShare.SubShares[set].SetBit(p.State.pShare.SubShares[set], 1, 0)
			p.State.pShare.SubShares[set].SetBit(p.State.pShare.SubShares[set], 0, 0)
			if slices.Contains(p.ExpTable[p.MySharingId], set) {
				adjust += k
			}
		}
	}
	p.State.pShareAdjust = adjust

	return &Round4Broadcast{PShareAdjust: p.State.pShareAdjust}
}

func (p *Participant) Round5(bIn network.RoundMessages[types.ThresholdProtocol, *Round4Broadcast]) *replicated.IntShare {
	for sharingId, identityKey := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		in, _ := bIn.Get(identityKey)
		p.State.pShareAdjust += in.PShareAdjust
	}

	firstSet := replicated.SharingIdSet((1 << (p.Protocol.Threshold() - 1)) - 1)
	if _, ok := p.State.pShare.SubShares[firstSet]; ok {
		p.State.pShare.SubShares[firstSet].Add(p.State.pShare.SubShares[firstSet], big.NewInt(int64(p.State.pShareAdjust)))
	}

	return p.State.pShare
}

func valuesSortedByKeys[M ~map[K]V, K cmp.Ordered, V any](in M) []V {
	out := []V{}
	for _, k := range slices.Sorted(maps.Keys(in)) {
		out = append(out, in[k])
	}

	return out
}
