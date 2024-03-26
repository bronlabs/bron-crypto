package bignum

import (
	"encoding/hex"
	"github.com/copperexchange/krypton-primitives/pkg/base/bignum/internal/impl"
	"github.com/cronokirby/saferith"
)

type CrtParams struct {
	m1      *saferith.Modulus
	phiM1   *saferith.Modulus
	m2      *saferith.Modulus
	phiM2   *saferith.Modulus
	m1InvM2 *saferith.Nat
}

func NewCrtParams(m1, phiM1, m2, phiM2 *saferith.Modulus, m1InvM2 *saferith.Nat) CrtParams {
	return CrtParams{
		m1:      m1,
		phiM1:   phiM1,
		m2:      m2,
		phiM2:   phiM2,
		m1InvM2: m1InvM2,
	}
}

func (p *CrtParams) GetM1() *saferith.Modulus {
	return p.m1
}

func (p *CrtParams) GetPhiM1() *saferith.Modulus {
	return p.phiM1
}

func (p *CrtParams) GetM2() *saferith.Modulus {
	return p.m2
}

func (p *CrtParams) GetPhiM2() *saferith.Modulus {
	return p.phiM2
}

func (p *CrtParams) GetM1InvM2() *saferith.Nat {
	return p.m1InvM2
}

func ExpCrt(crtParams *CrtParams, base, exponent *saferith.Nat, modulus *saferith.Modulus) *saferith.Nat {
	eModPhiM1 := new(saferith.Nat).Mod(exponent, crtParams.phiM1)
	eModPhiM2 := new(saferith.Nat).Mod(exponent, crtParams.phiM2)
	r1 := new(saferith.Nat).Exp(base, eModPhiM1, crtParams.m1)
	r2 := new(saferith.Nat).Exp(base, eModPhiM2, crtParams.m2)
	t1 := new(saferith.Nat).ModSub(r2, r1, crtParams.m2)
	println("A ", hex.EncodeToString(r2.Bytes()))
	t2 := new(saferith.Nat).ModMul(t1, crtParams.m1InvM2, crtParams.m2)
	t3 := new(saferith.Nat).ModMul(t2, crtParams.m1.Nat(), modulus)
	return new(saferith.Nat).ModAdd(t3, r1, modulus)
}

func FastExpCrt(params *CrtParams, base, exponent *saferith.Nat, modulus *saferith.Modulus) *saferith.Nat {
	bnCtx := impl.NewBigNumCtx()
	defer impl.FreeBigNumCtx(bnCtx)

	modulusBn := impl.InitBigNum(&impl.BoringBigNum{}).SetBytes(modulus.Bytes())
	defer impl.FreeBigNum(modulusBn)

	modulusMontCtx := impl.NewMontCtx(modulusBn, bnCtx)
	defer impl.FreeMontCtx(modulusMontCtx)

	exponentBn := impl.InitBigNum(&impl.BoringBigNum{}).SetBytes(exponent.Bytes())
	defer impl.FreeBigNum(exponentBn)

	baseBn := impl.InitBigNum(&impl.BoringBigNum{}).SetBytes(base.Bytes())
	defer impl.FreeBigNum(baseBn)

	phiM1Bn := impl.InitBigNum(&impl.BoringBigNum{}).SetBytes(params.phiM1.Bytes())
	defer impl.FreeBigNum(phiM1Bn)

	phiM2Bn := impl.InitBigNum(&impl.BoringBigNum{}).SetBytes(params.phiM2.Bytes())
	defer impl.FreeBigNum(phiM2Bn)

	eModPhiM1Bn := impl.InitBigNum(&impl.BoringBigNum{}).Mod(exponentBn, phiM1Bn, bnCtx)
	defer impl.FreeBigNum(eModPhiM1Bn)

	eModPhiM2Bn := impl.InitBigNum(&impl.BoringBigNum{}).Mod(exponentBn, phiM2Bn, bnCtx)
	defer impl.FreeBigNum(eModPhiM2Bn)

	m1Bn := impl.InitBigNum(&impl.BoringBigNum{}).SetBytes(params.m1.Bytes())
	defer impl.FreeBigNum(m1Bn)

	m2Bn := impl.InitBigNum(&impl.BoringBigNum{}).SetBytes(params.m2.Bytes())
	defer impl.FreeBigNum(m2Bn)

	m1MontCtx := impl.NewMontCtx(m1Bn, bnCtx)
	defer impl.FreeMontCtx(m1MontCtx)

	m2MontCtx := impl.NewMontCtx(m2Bn, bnCtx)
	defer impl.FreeMontCtx(m2MontCtx)

	baseModM1Bn := impl.InitBigNum(&impl.BoringBigNum{}).Mod(baseBn, m1Bn, bnCtx)
	defer impl.FreeBigNum(baseModM1Bn)

	baseModM2Bn := impl.InitBigNum(&impl.BoringBigNum{}).Mod(baseBn, m2Bn, bnCtx)
	defer impl.FreeBigNum(baseModM2Bn)

	r1Bn := impl.InitBigNum(&impl.BoringBigNum{}).Exp(baseModM1Bn, eModPhiM1Bn, m1Bn, m1MontCtx, bnCtx)
	defer impl.FreeBigNum(r1Bn)

	r2Bn := impl.InitBigNum(&impl.BoringBigNum{}).Exp(baseModM2Bn, eModPhiM2Bn, m2Bn, m2MontCtx, bnCtx)
	defer impl.FreeBigNum(r2Bn)

	t1Bn := impl.InitBigNum(&impl.BoringBigNum{}).ModSub(r2Bn, r1Bn, m2Bn, bnCtx)
	defer impl.FreeBigNum(t1Bn)
	println("B ", hex.EncodeToString(r2Bn.Bytes()))

	m1InvM2Bn := impl.InitBigNum(&impl.BoringBigNum{}).SetBytes(params.m1InvM2.Bytes())
	defer impl.FreeBigNum(m1InvM2Bn)

	t2Bn := impl.InitBigNum(&impl.BoringBigNum{}).ModMul(t1Bn, m1InvM2Bn, m2Bn, bnCtx)
	defer impl.FreeBigNum(t2Bn)

	t3Bn := impl.InitBigNum(&impl.BoringBigNum{}).ModMul(t2Bn, m1Bn, modulusBn, bnCtx)
	defer impl.FreeBigNum(t3Bn)

	r := impl.InitBigNum(&impl.BoringBigNum{}).ModAdd(t3Bn, r1Bn, modulusBn, bnCtx)
	return new(saferith.Nat).SetBytes(r.Bytes())
}
