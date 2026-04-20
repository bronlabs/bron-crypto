package znstar

import (
	"github.com/fxamacker/cbor/v2"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/internal/tags"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/modular"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
)

var (
	_ cbor.Marshaler   = (*RSAGroupKnownOrder)(nil)
	_ cbor.Unmarshaler = (*RSAGroupKnownOrder)(nil)

	_ cbor.Marshaler   = (*RSAGroupElementKnownOrder)(nil)
	_ cbor.Unmarshaler = (*RSAGroupElementKnownOrder)(nil)

	_ cbor.Marshaler   = (*RSAGroupUnknownOrder)(nil)
	_ cbor.Unmarshaler = (*RSAGroupUnknownOrder)(nil)

	_ cbor.Marshaler   = (*RSAGroupElementUnknownOrder)(nil)
	_ cbor.Unmarshaler = (*RSAGroupElementUnknownOrder)(nil)

	_ cbor.Marshaler   = (*PaillierGroupKnownOrder)(nil)
	_ cbor.Unmarshaler = (*PaillierGroupKnownOrder)(nil)

	_ cbor.Marshaler   = (*PaillierGroupElementKnownOrder)(nil)
	_ cbor.Unmarshaler = (*PaillierGroupElementKnownOrder)(nil)

	_ cbor.Marshaler   = (*PaillierGroupUnknownOrder)(nil)
	_ cbor.Unmarshaler = (*PaillierGroupUnknownOrder)(nil)

	_ cbor.Marshaler   = (*PaillierGroupElementUnknownOrder)(nil)
	_ cbor.Unmarshaler = (*PaillierGroupElementUnknownOrder)(nil)
)

// CBOR type tags for the serialised forms of every group and element
// variant in this package. Each tag encodes (a) whether the payload is a
// group or an element and (b) whether it was produced under the trapdoor-
// aware known-order view or the trapdoor-free unknown-order view, so that
// a decoder can refuse to promote an unknown-order payload into a known-
// order type by mistake — a conversion that would either be a bug or an
// attempt to strip information.
const (
	RSAGroupKnownOrderTag               = tags.RSAGroupKnownOrderTag
	RSAGroupKnownOrderElementTag        = tags.RSAGroupKnownOrderElementTag
	RSAGroupUnknownOrderTag             = tags.RSAGroupUnknownOrderTag
	RSAGroupUnknownOrderElementTag      = tags.RSAGroupUnknownOrderElementTag
	PaillierGroupKnownOrderTag          = tags.PaillierGroupKnownOrderTag
	PaillierGroupKnownOrderElementTag   = tags.PaillierGroupKnownOrderElementTag
	PaillierGroupUnknownOrderTag        = tags.PaillierGroupUnknownOrderTag
	PaillierGroupUnknownOrderElementTag = tags.PaillierGroupUnknownOrderElementTag
)

func init() {
	serde.Register[*RSAGroupKnownOrder](RSAGroupKnownOrderTag)
	serde.Register[*RSAGroupElementKnownOrder](RSAGroupKnownOrderElementTag)
	serde.Register[*RSAGroupUnknownOrder](RSAGroupUnknownOrderTag)
	serde.Register[*RSAGroupElementUnknownOrder](RSAGroupUnknownOrderElementTag)
	serde.Register[*PaillierGroupKnownOrder](PaillierGroupKnownOrderTag)
	serde.Register[*PaillierGroupElementKnownOrder](PaillierGroupKnownOrderElementTag)
	serde.Register[*PaillierGroupUnknownOrder](PaillierGroupUnknownOrderTag)
	serde.Register[*PaillierGroupElementUnknownOrder](PaillierGroupUnknownOrderElementTag)
}

type rsaGroupKnownOrderDTO struct {
	P *num.NatPlus `cbor:"p"`
	Q *num.NatPlus `cbor:"q"`
}

type rsaGroupUnknownOrderDTO struct {
	Modulus *num.NatPlus `cbor:"modulus"`
}

type rsaGroupUnknownOrderElementDTO struct {
	V          *num.Uint              `cbor:"v"`
	Arithmetic *modular.SimpleModulus `cbor:"arithmetic"`
}

type rsaGroupKnownOrderElementDTO struct {
	V          *num.Uint                `cbor:"v"`
	Arithmetic *modular.OddPrimeFactors `cbor:"arithmetic"`
}

type paillierGroupKnownOrderDTO struct {
	P *num.NatPlus `cbor:"p"`
	Q *num.NatPlus `cbor:"q"`
}

type paillierGroupUnknownOrderDTO struct {
	N *num.NatPlus `cbor:"n"`
}

type paillierGroupKnownOrderElementDTO struct {
	V          *num.Uint                      `cbor:"v"`
	Arithmetic *modular.OddPrimeSquareFactors `cbor:"arithmetic"`
}

type paillierGroupUnknownOrderElementDTO struct {
	V          *num.Uint              `cbor:"v"`
	Arithmetic *modular.SimpleModulus `cbor:"arithmetic"`
	N          *num.NatPlus           `cbor:"n"`
}

// ========== CBOR Serialisation ==========.

// MarshalCBOR serialises the Paillier group. A known-order group is emitted
// as (p, q) so that decoders can reconstruct the CRT arithmetic; an
// unknown-order group is emitted as the single modulus N. Crucially the
// two shapes are distinguished by CBOR tag, which prevents a malicious
// peer from re-tagging an unknown-order blob and inducing a known-order
// reconstruction without primes.
func (pg *PaillierGroup[X]) MarshalCBOR() ([]byte, error) {
	var tag uint64
	switch any(pg.arith).(type) {
	case *modular.OddPrimeSquareFactors:
		tag = PaillierGroupKnownOrderTag
		p, err := num.NPlus().FromModulusCT(any(pg.arith).(*modular.OddPrimeSquareFactors).P.Factor) //nolint:errcheck // false positive
		if err != nil {
			return nil, errs.Wrap(err)
		}
		q, err := num.NPlus().FromModulusCT(any(pg.arith).(*modular.OddPrimeSquareFactors).Q.Factor) //nolint:errcheck // false positive
		if err != nil {
			return nil, errs.Wrap(err)
		}
		dto := &paillierGroupKnownOrderDTO{
			P: p,
			Q: q,
		}
		return serde.MarshalCBORTagged(dto, tag)
	case *modular.SimpleModulus:
		tag = PaillierGroupUnknownOrderTag
		dto := &paillierGroupUnknownOrderDTO{
			N: pg.n,
		}
		return serde.MarshalCBORTagged(dto, tag)
	default:
		return nil, errs.Wrap(ErrFailed).WithMessage("unknown arithmetic type for PaillierGroup")
	}
}

// UnmarshalCBOR reconstructs a Paillier group from its serialised form.
// The concrete arithmetic type (OddPrimeSquareFactors vs SimpleModulus)
// is used to dispatch between known-order and unknown-order decoders.
// For the known-order case the primality of p, q is re-checked by
// NewPaillierGroup so that a malformed payload cannot smuggle a
// composite into CRT-backed arithmetic; for the unknown-order case, the
// supplied N² is verified to equal N·N so that the two redundant fields
// cannot be set inconsistently.
func (pg *PaillierGroup[X]) UnmarshalCBOR(data []byte) error {
	switch any(pg.arith).(type) {
	case *modular.OddPrimeSquareFactors:
		dto, err := serde.UnmarshalCBOR[paillierGroupKnownOrderDTO](data)
		if err != nil {
			return errs.Wrap(err)
		}
		reconstructed, err := NewPaillierGroup(dto.P, dto.Q)
		if err != nil {
			return errs.Wrap(err)
		}
		*pg = *any(reconstructed).(*PaillierGroup[X]) //nolint:errcheck // false positive
		return nil
	case *modular.SimpleModulus:
		dto, err := serde.UnmarshalCBOR[paillierGroupUnknownOrderDTO](data)
		if err != nil {
			return errs.Wrap(err)
		}
		n2 := dto.N.Square()
		reconstructed, err := NewPaillierGroupOfUnknownOrder(n2, dto.N)
		if err != nil {
			return errs.Wrap(err)
		}
		*pg = *any(reconstructed).(*PaillierGroup[X]) //nolint:errcheck // false positive
		return nil
	default:
		return errs.Wrap(ErrFailed).WithMessage("unknown arithmetic type for PaillierGroup in UnmarshalCBOR")
	}
}

// MarshalCBOR serialises a Paillier group element. The payload carries
// the element's value alongside the arithmetic object so that the
// receiving side can re-derive the ambient group. Known- and unknown-
// order elements use distinct tags to prevent silent promotion between
// views on the wire.
func (u *PaillierGroupElement[X]) MarshalCBOR() ([]byte, error) {
	var tag uint64
	switch any(u.arith).(type) {
	case *modular.OddPrimeSquareFactors:
		tag = PaillierGroupKnownOrderElementTag
		dto := &paillierGroupKnownOrderElementDTO{
			V:          u.v,
			Arithmetic: any(u.arith).(*modular.OddPrimeSquareFactors), //nolint:errcheck // false positive
		}
		return serde.MarshalCBORTagged(dto, tag)
	case *modular.SimpleModulus:
		tag = PaillierGroupUnknownOrderElementTag
		dto := &paillierGroupUnknownOrderElementDTO{
			V:          u.v,
			Arithmetic: any(u.arith).(*modular.SimpleModulus), //nolint:errcheck // false positive
			N:          u.n,
		}
		return serde.MarshalCBORTagged(dto, tag)
	default:
		return nil, errs.Wrap(ErrFailed).WithMessage("unknown arithmetic type for PaillierGroupElement")
	}
}

// UnmarshalCBOR reconstructs a Paillier group element. When the receiver
// already has a concrete arithmetic (known- or unknown-order) it
// dispatches directly; when the receiver is in the zero state — as
// happens on the very first UnmarshalCBOR call into a freshly allocated
// value — both tag shapes are tried in turn so that the decoder can
// determine the view from the payload alone. In every branch the
// element is re-fetched via FromUint, which enforces the coprime-with-N
// unit invariant on deserialised inputs (matching the general rule that
// deserialisation paths must sanitise).
func (u *PaillierGroupElement[X]) UnmarshalCBOR(data []byte) error {
	switch any(u.arith).(type) {
	case *modular.OddPrimeSquareFactors:
		dto, err := serde.UnmarshalCBOR[paillierGroupKnownOrderElementDTO](data)
		if err != nil {
			return errs.Wrap(err)
		}
		p, err := num.NPlus().FromModulusCT(dto.Arithmetic.P.Factor)
		if err != nil {
			return errs.Wrap(err)
		}
		q, err := num.NPlus().FromModulusCT(dto.Arithmetic.Q.Factor)
		if err != nil {
			return errs.Wrap(err)
		}
		g, err := NewPaillierGroup(p, q)
		if err != nil {
			return errs.Wrap(err)
		}
		elem, err := g.FromUint(dto.V)
		if err != nil {
			return errs.Wrap(err)
		}
		*u = *any(elem).(*PaillierGroupElement[X]) //nolint:errcheck // false positive
		return nil
	case *modular.SimpleModulus:
		dto, err := serde.UnmarshalCBOR[paillierGroupUnknownOrderElementDTO](data)
		if err != nil {
			return errs.Wrap(err)
		}
		n2 := dto.N.Square()
		g, err := NewPaillierGroupOfUnknownOrder(n2, dto.N)
		if err != nil {
			return errs.Wrap(err)
		}
		elem, err := g.FromUint(dto.V)
		if err != nil {
			return errs.Wrap(err)
		}
		*u = *any(elem).(*PaillierGroupElement[X]) //nolint:errcheck // false positive
		return nil
	default:
		// For initial unmarshal when arith is zero value, try both
		if dtoKnown, err := serde.UnmarshalCBOR[paillierGroupKnownOrderElementDTO](data); err == nil {
			p, err := num.NPlus().FromModulusCT(dtoKnown.Arithmetic.P.Factor)
			if err != nil {
				return errs.Wrap(err)
			}
			q, err := num.NPlus().FromModulusCT(dtoKnown.Arithmetic.Q.Factor)
			if err != nil {
				return errs.Wrap(err)
			}
			g, err := NewPaillierGroup(p, q)
			if err != nil {
				return errs.Wrap(err)
			}
			elem, err := g.FromUint(dtoKnown.V)
			if err != nil {
				return errs.Wrap(err)
			}
			*u = *any(elem).(*PaillierGroupElement[X]) //nolint:errcheck // false positive
			return nil
		}
		dto, err := serde.UnmarshalCBOR[paillierGroupUnknownOrderElementDTO](data)
		if err != nil {
			return errs.Wrap(err)
		}
		n2 := dto.N.Square()
		g, err := NewPaillierGroupOfUnknownOrder(n2, dto.N)
		if err != nil {
			return errs.Wrap(err)
		}
		elem, err := g.FromUint(dto.V)
		if err != nil {
			return errs.Wrap(err)
		}
		*u = *any(elem).(*PaillierGroupElement[X]) //nolint:errcheck // false positive
		return nil
	}
}

// MarshalCBOR serialises the RSA group. A known-order group emits (p, q)
// so that decoders can rebuild the CRT arithmetic; an unknown-order
// group emits only its modulus. The two forms live under distinct CBOR
// tags so that a payload with only a modulus can never be silently
// decoded as if it carried a factorisation.
func (rg *RSAGroup[X]) MarshalCBOR() ([]byte, error) {
	// Determine tag based on arithmetic type
	var tag uint64
	switch any(rg.arith).(type) {
	case *modular.OddPrimeFactors:
		tag = RSAGroupKnownOrderTag
		p, err := num.NPlus().FromModulusCT(any(rg.arith).(*modular.OddPrimeFactors).Params.P) //nolint:errcheck // false positive
		if err != nil {
			return nil, errs.Wrap(err)
		}
		q, err := num.NPlus().FromModulusCT(any(rg.arith).(*modular.OddPrimeFactors).Params.Q) //nolint:errcheck // false positive
		if err != nil {
			return nil, errs.Wrap(err)
		}
		dto := &rsaGroupKnownOrderDTO{
			P: p,
			Q: q,
		}
		return serde.MarshalCBORTagged(dto, tag)
	case *modular.SimpleModulus:
		tag = RSAGroupUnknownOrderTag
		dto := &rsaGroupUnknownOrderDTO{
			Modulus: rg.Modulus(),
		}
		return serde.MarshalCBORTagged(dto, tag)
	default:
		return nil, errs.Wrap(ErrFailed).WithMessage("unknown arithmetic type for RSAGroup")
	}
}

// UnmarshalCBOR reconstructs an RSA group from its serialised form.
// Dispatches on the concrete arithmetic type: the known-order branch
// re-runs primality checks on p, q through NewRSAGroup so that a
// malformed payload cannot inject a composite "prime" and downgrade the
// CRT computations to nonsense; the unknown-order branch only requires
// a well-formed modulus.
func (rg *RSAGroup[X]) UnmarshalCBOR(data []byte) error {
	// Determine which type based on X
	switch any(rg.arith).(type) {
	case *modular.OddPrimeFactors:
		dto, err := serde.UnmarshalCBOR[rsaGroupKnownOrderDTO](data)
		if err != nil {
			return errs.Wrap(err)
		}
		reconstructed, err := NewRSAGroup(dto.P, dto.Q)
		if err != nil {
			return errs.Wrap(err)
		}
		*rg = *any(reconstructed).(*RSAGroup[X]) //nolint:errcheck // false positive
		return nil
	case *modular.SimpleModulus:
		dto, err := serde.UnmarshalCBOR[rsaGroupUnknownOrderDTO](data)
		if err != nil {
			return errs.Wrap(err)
		}
		reconstructed, err := NewRSAGroupOfUnknownOrder(dto.Modulus)
		if err != nil {
			return errs.Wrap(err)
		}
		*rg = *any(reconstructed).(*RSAGroup[X]) //nolint:errcheck // false positive
		return nil
	default:
		return errs.Wrap(ErrFailed).WithMessage("unknown arithmetic type in UnmarshalCBOR")
	}
}

// MarshalCBOR serialises an RSA group element together with its
// arithmetic object, so that the decoder can rebuild both the ambient
// group and the element in a single pass. Known- and unknown-order
// elements use distinct tags to preserve the prover/verifier distinction
// over the wire.
func (u *RSAGroupElement[X]) MarshalCBOR() ([]byte, error) {
	var tag uint64
	switch any(u.arith).(type) {
	case *modular.OddPrimeFactors:
		tag = RSAGroupKnownOrderElementTag
		dto := &rsaGroupKnownOrderElementDTO{
			V:          u.v,
			Arithmetic: any(u.arith).(*modular.OddPrimeFactors), //nolint:errcheck // false positive
		}
		return serde.MarshalCBORTagged(dto, tag)
	case *modular.SimpleModulus:
		tag = RSAGroupUnknownOrderElementTag
		dto := &rsaGroupUnknownOrderElementDTO{
			V:          u.v,
			Arithmetic: any(u.arith).(*modular.SimpleModulus), //nolint:errcheck // false positive
		}
		return serde.MarshalCBORTagged(dto, tag)
	default:
		return nil, errs.Wrap(ErrFailed).WithMessage("unknown arithmetic type for RSAGroupElement")
	}
}

// UnmarshalCBOR reconstructs an RSA group element. As with the Paillier
// variant, the receiver's concrete arithmetic dispatches the decoder;
// a zero-valued receiver triggers a fallback that tries both tag shapes
// so that decoders built against a naked RSAGroupElement[X] can still
// handle inputs of either view. The underlying value is always
// re-ingested through FromUint, which enforces the unit invariant on
// untrusted input.
func (u *RSAGroupElement[X]) UnmarshalCBOR(data []byte) error {
	switch any(u.arith).(type) {
	case *modular.OddPrimeFactors:
		dto, err := serde.UnmarshalCBOR[rsaGroupKnownOrderElementDTO](data)
		if err != nil {
			return errs.Wrap(err)
		}
		p, err := num.NPlus().FromModulusCT(dto.Arithmetic.Params.P)
		if err != nil {
			return errs.Wrap(err)
		}
		q, err := num.NPlus().FromModulusCT(dto.Arithmetic.Params.Q)
		if err != nil {
			return errs.Wrap(err)
		}
		g, err := NewRSAGroup(p, q)
		if err != nil {
			return errs.Wrap(err)
		}
		elem, err := g.FromUint(dto.V)
		if err != nil {
			return errs.Wrap(err)
		}
		*u = *any(elem).(*RSAGroupElement[X]) //nolint:errcheck // false positive
		return nil
	case *modular.SimpleModulus:
		dto, err := serde.UnmarshalCBOR[rsaGroupUnknownOrderElementDTO](data)
		if err != nil {
			return errs.Wrap(err)
		}
		g, err := NewRSAGroupOfUnknownOrder(dto.V.Modulus())
		if err != nil {
			return errs.Wrap(err)
		}
		elem, err := g.FromUint(dto.V)
		if err != nil {
			return errs.Wrap(err)
		}
		*u = *any(elem).(*RSAGroupElement[X]) //nolint:errcheck // false positive
		return nil
	default:
		// For initial unmarshal when arith is zero value, try both
		if dtoKnown, err := serde.UnmarshalCBOR[rsaGroupKnownOrderElementDTO](data); err == nil {
			p, err := num.NPlus().FromModulusCT(dtoKnown.Arithmetic.Params.P)
			if err != nil {
				return errs.Wrap(err)
			}
			q, err := num.NPlus().FromModulusCT(dtoKnown.Arithmetic.Params.Q)
			if err != nil {
				return errs.Wrap(err)
			}
			g, err := NewRSAGroup(p, q)
			if err != nil {
				return errs.Wrap(err)
			}
			elem, err := g.FromUint(dtoKnown.V)
			if err != nil {
				return errs.Wrap(err)
			}
			*u = *any(elem).(*RSAGroupElement[X]) //nolint:errcheck // false positive
			return nil
		}
		dto, err := serde.UnmarshalCBOR[rsaGroupUnknownOrderElementDTO](data)
		if err != nil {
			return errs.Wrap(err)
		}
		g, err := NewRSAGroupOfUnknownOrder(dto.V.Modulus())
		if err != nil {
			return errs.Wrap(err)
		}
		elem, err := g.FromUint(dto.V)
		if err != nil {
			return errs.Wrap(err)
		}
		*u = *any(elem).(*RSAGroupElement[X]) //nolint:errcheck // false positive
		return nil
	}
}
