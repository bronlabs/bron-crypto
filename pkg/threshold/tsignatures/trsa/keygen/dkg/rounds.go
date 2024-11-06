package dkg

import (
	nativeRsa "crypto/rsa"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/replicated"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/trsa"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/trsa/keygen/dkg/subprotocols/inv_mod"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/trsa/keygen/dkg/subprotocols/prob_prime_two_three"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/trsa/keygen/dkg/subprotocols/sieve"
	"math/big"
)

const (
	ParamE = 65537
)

func (p *Participant) Round1() (p2pOut network.RoundMessages[types.ThresholdProtocol, *Round1P2P]) {
	p.State.Sieve = sieve.NewParticipant(p.Tape, p.MyIdentityKey, p.Protocol, p.PrimeBitLen, p.Prng)
	sieveR1 := p.State.Sieve.Round1()

	return sieveR1
}

func (p *Participant) Round2(p2pIn network.RoundMessages[types.ThresholdProtocol, *Round1P2P]) (p2pOut network.RoundMessages[types.ThresholdProtocol, *Round2P2P]) {
	sieveR2 := p.State.Sieve.Round2(p2pIn)

	return sieveR2
}

func (p *Participant) Round3(p2pIn network.RoundMessages[types.ThresholdProtocol, *Round2P2P]) (bOut *Round3Broadcast) {
	sieveR3 := p.State.Sieve.Round3(p2pIn)

	return sieveR3
}

func (p *Participant) Round4(bIn network.RoundMessages[types.ThresholdProtocol, *Round3Broadcast]) (p2pOut network.RoundMessages[types.ThresholdProtocol, *Round4P2P], ok bool) {
	p.State.pShare, p.State.qShare, p.State.n, ok = p.State.Sieve.Round4(bIn)
	if !ok {
		return nil, false
	}

	p.State.ProbPrimeP = prob_prime_two_three.NewParticipant(p.Tape, p.MyIdentityKey, p.Protocol, p.State.n, p.Prng)
	ProbPrimePR1, _ := p.State.ProbPrimeP.Round1(p.State.pShare, p.State.qShare)

	p.State.ProbPrimeQ = prob_prime_two_three.NewParticipant(p.Tape, p.MyIdentityKey, p.Protocol, p.State.n, p.Prng)
	ProbPrimeQR1, _ := p.State.ProbPrimeQ.Round1(p.State.qShare, p.State.pShare)

	p2pOut = network.NewRoundMessages[types.ThresholdProtocol, *Round4P2P]()
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		out := &Round4P2P{}
		out.PProbPrimeR1, _ = ProbPrimePR1.Get(id)
		out.QProbPrimeR1, _ = ProbPrimeQR1.Get(id)
		p2pOut.Put(id, out)
	}

	return p2pOut, true
}

func (p *Participant) Round5(p2pIn network.RoundMessages[types.ThresholdProtocol, *Round4P2P]) (p2pOut network.RoundMessages[types.ThresholdProtocol, *Round5P2P]) {
	pr1 := network.NewRoundMessages[types.ThresholdProtocol, *prob_prime_two_three.Round1P2P]()
	qr1 := network.NewRoundMessages[types.ThresholdProtocol, *prob_prime_two_three.Round1P2P]()
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		in, _ := p2pIn.Get(id)
		pr1.Put(id, in.PProbPrimeR1)
		qr1.Put(id, in.QProbPrimeR1)
	}

	ProbPrimePR2 := p.State.ProbPrimeP.Round2(pr1)
	ProbPrimeQR2 := p.State.ProbPrimeQ.Round2(qr1)

	p2pOut = network.NewRoundMessages[types.ThresholdProtocol, *Round5P2P]()
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		out := &Round5P2P{}
		out.PProbPrimeR2, _ = ProbPrimePR2.Get(id)
		out.QProbPrimeR2, _ = ProbPrimeQR2.Get(id)
		p2pOut.Put(id, out)
	}

	return p2pOut
}

func (p *Participant) Round6(p2pIn network.RoundMessages[types.ThresholdProtocol, *Round5P2P]) (p2pOut network.RoundMessages[types.ThresholdProtocol, *Round6P2P]) {
	pr2 := network.NewRoundMessages[types.ThresholdProtocol, *prob_prime_two_three.Round2P2P]()
	qr2 := network.NewRoundMessages[types.ThresholdProtocol, *prob_prime_two_three.Round2P2P]()
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		in, _ := p2pIn.Get(id)
		pr2.Put(id, in.PProbPrimeR2)
		qr2.Put(id, in.QProbPrimeR2)
	}

	ProbPrimePR3 := p.State.ProbPrimeP.Round3(pr2)
	ProbPrimeQR3 := p.State.ProbPrimeQ.Round3(qr2)

	p2pOut = network.NewRoundMessages[types.ThresholdProtocol, *Round6P2P]()
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		out := &Round6P2P{}
		out.PProbPrimeR3, _ = ProbPrimePR3.Get(id)
		out.QProbPrimeR3, _ = ProbPrimeQR3.Get(id)
		p2pOut.Put(id, out)
	}

	return p2pOut
}

func (p *Participant) Round7(p2pIn network.RoundMessages[types.ThresholdProtocol, *Round6P2P]) (p2pOut network.RoundMessages[types.ThresholdProtocol, *Round7P2P]) {
	pr3 := network.NewRoundMessages[types.ThresholdProtocol, *prob_prime_two_three.Round3P2P]()
	qr3 := network.NewRoundMessages[types.ThresholdProtocol, *prob_prime_two_three.Round3P2P]()
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		in, _ := p2pIn.Get(id)
		pr3.Put(id, in.PProbPrimeR3)
		qr3.Put(id, in.QProbPrimeR3)
	}

	ProbPrimePR4 := p.State.ProbPrimeP.Round4(pr3)
	ProbPrimeQR4 := p.State.ProbPrimeQ.Round4(qr3)

	p2pOut = network.NewRoundMessages[types.ThresholdProtocol, *Round7P2P]()
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		out := &Round7P2P{}
		out.PProbPrimeR4, _ = ProbPrimePR4.Get(id)
		out.QProbPrimeR4, _ = ProbPrimeQR4.Get(id)
		p2pOut.Put(id, out)
	}

	return p2pOut
}

func (p *Participant) Round8(p2pIn network.RoundMessages[types.ThresholdProtocol, *Round7P2P]) (p2pOut network.RoundMessages[types.ThresholdProtocol, *Round8P2P]) {
	pr4 := network.NewRoundMessages[types.ThresholdProtocol, *prob_prime_two_three.Round4P2P]()
	qr4 := network.NewRoundMessages[types.ThresholdProtocol, *prob_prime_two_three.Round4P2P]()
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		in, _ := p2pIn.Get(id)
		pr4.Put(id, in.PProbPrimeR4)
		qr4.Put(id, in.QProbPrimeR4)
	}

	ProbPrimePR5 := p.State.ProbPrimeP.Round5(pr4)
	ProbPrimeQR5 := p.State.ProbPrimeQ.Round5(qr4)

	p2pOut = network.NewRoundMessages[types.ThresholdProtocol, *Round8P2P]()
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		out := &Round8P2P{}
		out.PProbPrimeR5, _ = ProbPrimePR5.Get(id)
		out.QProbPrimeR5, _ = ProbPrimeQR5.Get(id)
		p2pOut.Put(id, out)
	}

	return p2pOut
}

func (p *Participant) Round9(p2pIn network.RoundMessages[types.ThresholdProtocol, *Round8P2P]) (p2pOut network.RoundMessages[types.ThresholdProtocol, *Round9P2P]) {
	pr5 := network.NewRoundMessages[types.ThresholdProtocol, *prob_prime_two_three.Round5P2P]()
	qr5 := network.NewRoundMessages[types.ThresholdProtocol, *prob_prime_two_three.Round5P2P]()
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		in, _ := p2pIn.Get(id)
		pr5.Put(id, in.PProbPrimeR5)
		qr5.Put(id, in.QProbPrimeR5)
	}

	ProbPrimePR6 := p.State.ProbPrimeP.Round6(pr5)
	ProbPrimeQR6 := p.State.ProbPrimeQ.Round6(qr5)

	p2pOut = network.NewRoundMessages[types.ThresholdProtocol, *Round9P2P]()
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		out := &Round9P2P{}
		out.PProbPrimeR6, _ = ProbPrimePR6.Get(id)
		out.QProbPrimeR6, _ = ProbPrimeQR6.Get(id)
		p2pOut.Put(id, out)
	}

	return p2pOut
}

func (p *Participant) Round10(p2pIn network.RoundMessages[types.ThresholdProtocol, *Round9P2P]) (p2pOut network.RoundMessages[types.ThresholdProtocol, *Round10P2P]) {
	pr6 := network.NewRoundMessages[types.ThresholdProtocol, *prob_prime_two_three.Round6P2P]()
	qr6 := network.NewRoundMessages[types.ThresholdProtocol, *prob_prime_two_three.Round6P2P]()
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		in, _ := p2pIn.Get(id)
		pr6.Put(id, in.PProbPrimeR6)
		qr6.Put(id, in.QProbPrimeR6)
	}

	ProbPrimePR7 := p.State.ProbPrimeP.Round7(pr6)
	ProbPrimeQR7 := p.State.ProbPrimeQ.Round7(qr6)

	p2pOut = network.NewRoundMessages[types.ThresholdProtocol, *Round10P2P]()
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		out := &Round10P2P{}
		out.PProbPrimeR7, _ = ProbPrimePR7.Get(id)
		out.QProbPrimeR7, _ = ProbPrimeQR7.Get(id)
		p2pOut.Put(id, out)
	}

	return p2pOut
}

func (p *Participant) Round11(p2pIn network.RoundMessages[types.ThresholdProtocol, *Round10P2P]) (p2pOut network.RoundMessages[types.ThresholdProtocol, *Round11P2P]) {
	pr7 := network.NewRoundMessages[types.ThresholdProtocol, *prob_prime_two_three.Round7P2P]()
	qr7 := network.NewRoundMessages[types.ThresholdProtocol, *prob_prime_two_three.Round7P2P]()
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		in, _ := p2pIn.Get(id)
		pr7.Put(id, in.PProbPrimeR7)
		qr7.Put(id, in.QProbPrimeR7)
	}

	ProbPrimePR8 := p.State.ProbPrimeP.Round8(pr7)
	ProbPrimeQR8 := p.State.ProbPrimeQ.Round8(qr7)

	p2pOut = network.NewRoundMessages[types.ThresholdProtocol, *Round11P2P]()
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		out := &Round11P2P{}
		out.PProbPrimeR8, _ = ProbPrimePR8.Get(id)
		out.QProbPrimeR8, _ = ProbPrimeQR8.Get(id)
		p2pOut.Put(id, out)
	}

	return p2pOut
}

func (p *Participant) Round12(p2pIn network.RoundMessages[types.ThresholdProtocol, *Round11P2P]) (p2pOut network.RoundMessages[types.ThresholdProtocol, *Round12P2P]) {
	pr8 := network.NewRoundMessages[types.ThresholdProtocol, *prob_prime_two_three.Round8P2P]()
	qr8 := network.NewRoundMessages[types.ThresholdProtocol, *prob_prime_two_three.Round8P2P]()
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		in, _ := p2pIn.Get(id)
		pr8.Put(id, in.PProbPrimeR8)
		qr8.Put(id, in.QProbPrimeR8)
	}

	ProbPrimePR9 := p.State.ProbPrimeP.Round9(pr8)
	ProbPrimeQR9 := p.State.ProbPrimeQ.Round9(qr8)

	p2pOut = network.NewRoundMessages[types.ThresholdProtocol, *Round12P2P]()
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		out := &Round12P2P{}
		out.PProbPrimeR9, _ = ProbPrimePR9.Get(id)
		out.QProbPrimeR9, _ = ProbPrimeQR9.Get(id)
		p2pOut.Put(id, out)
	}

	return p2pOut
}

func (p *Participant) Round13(p2pIn network.RoundMessages[types.ThresholdProtocol, *Round12P2P]) (p2pOut network.RoundMessages[types.ThresholdProtocol, *Round13P2P]) {
	pr9 := network.NewRoundMessages[types.ThresholdProtocol, *prob_prime_two_three.Round9P2P]()
	qr9 := network.NewRoundMessages[types.ThresholdProtocol, *prob_prime_two_three.Round9P2P]()
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		in, _ := p2pIn.Get(id)
		pr9.Put(id, in.PProbPrimeR9)
		qr9.Put(id, in.QProbPrimeR9)
	}

	ProbPrimePR10 := p.State.ProbPrimeP.Round10(pr9)
	ProbPrimeQR10 := p.State.ProbPrimeQ.Round10(qr9)

	p2pOut = network.NewRoundMessages[types.ThresholdProtocol, *Round13P2P]()
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		out := &Round13P2P{}
		out.PProbPrimeR10, _ = ProbPrimePR10.Get(id)
		out.QProbPrimeR10, _ = ProbPrimeQR10.Get(id)
		p2pOut.Put(id, out)
	}

	return p2pOut
}

func (p *Participant) Round14(p2pIn network.RoundMessages[types.ThresholdProtocol, *Round13P2P]) (bOut *Round14Broadcast) {
	pr10 := network.NewRoundMessages[types.ThresholdProtocol, *prob_prime_two_three.Round10P2P]()
	qr10 := network.NewRoundMessages[types.ThresholdProtocol, *prob_prime_two_three.Round10P2P]()
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		in, _ := p2pIn.Get(id)
		pr10.Put(id, in.PProbPrimeR10)
		qr10.Put(id, in.QProbPrimeR10)
	}

	ProbPrimePR11 := p.State.ProbPrimeP.Round11(pr10)
	ProbPrimeQR11 := p.State.ProbPrimeQ.Round11(qr10)

	bOut = &Round14Broadcast{
		PProbPrimeR11: ProbPrimePR11,
		QProbPrimeR11: ProbPrimeQR11,
	}

	return bOut
}

func (p *Participant) Round15(bIn network.RoundMessages[types.ThresholdProtocol, *Round14Broadcast]) (ok bool) {
	pr11 := network.NewRoundMessages[types.ThresholdProtocol, *prob_prime_two_three.Round11Broadcast]()
	qr11 := network.NewRoundMessages[types.ThresholdProtocol, *prob_prime_two_three.Round11Broadcast]()
	for sharingId, id := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}
		in, _ := bIn.Get(id)
		pr11.Put(id, in.PProbPrimeR11)
		qr11.Put(id, in.QProbPrimeR11)
	}

	pProbPrime := p.State.ProbPrimeP.Round12(pr11)
	qProbPrime := p.State.ProbPrimeQ.Round12(qr11)

	if pProbPrime && qProbPrime {
		return true
	}

	return false
}

func (p *Participant) Round16() network.RoundMessages[types.ThresholdProtocol, *Round16P2P] {
	p.State.phiShare = p.State.pShare.Neg().Sub(p.State.qShare).AddValue(p.State.n).AddValue(big.NewInt(1))
	p.State.InvMod = inv_mod.NewParticipant(p.Tape, p.MyIdentityKey, p.Protocol, p.PrimeBitLen, p.Prng)
	phiInvR1 := p.State.InvMod.Round1()

	return phiInvR1
}

func (p *Participant) Round17(p2pIn network.RoundMessages[types.ThresholdProtocol, *Round16P2P]) (p2pOut network.RoundMessages[types.ThresholdProtocol, *Round17P2P]) {
	phiInvR2 := p.State.InvMod.Round2(ParamE, p.State.phiShare, p2pIn)
	return phiInvR2
}

func (p *Participant) Round18(p2pIn network.RoundMessages[types.ThresholdProtocol, *Round17P2P]) (bOut *Round18Broadcast) {
	phiInvR3 := p.State.InvMod.Round3(p2pIn)
	return phiInvR3
}

func (p *Participant) Round19(bIn network.RoundMessages[types.ThresholdProtocol, *Round18Broadcast]) (shard *trsa.Shard, pk *nativeRsa.PublicKey, ok bool) {
	var dShare *replicated.IntShare
	dShare, ok = p.State.InvMod.Round4(bIn)
	if !ok {
		return nil, nil, false
	}
	e := ParamE

	pk = &nativeRsa.PublicKey{
		N: new(big.Int).Set(p.State.n),
		E: e,
	}

	shard = &trsa.Shard{
		PublicKey: nativeRsa.PublicKey{
			N: new(big.Int).Set(p.State.n),
			E: e,
		},
		PShare: p.State.pShare,
		QShare: p.State.qShare,
		DShare: dShare,
	}

	return shard, pk, true
}
