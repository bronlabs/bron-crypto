package curves_testutils

import (
	"encoding/binary"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	fu "github.com/copperexchange/krypton-primitives/pkg/base/fuzzutils"
)

var _ fu.ObjectAdapter[curves.Point] = (*PointAdapter)(nil)

type PointAdapter struct {
	curves.Curve
}

func NewPointAdapter(curve curves.Curve) fu.ObjectAdapter[curves.Point] {
	return &PointAdapter{Curve: curve}
}

func (pa *PointAdapter) Wrap(x fu.Underlyer) curves.Point {
	buffer := make([]byte, pa.ElementSize()+1)
	binary.LittleEndian.PutUint64(buffer[:8], x)
	p, err := pa.Element().FromAffineCompressed(buffer)
	if err != nil { // Default to hash if point creation fails
		p, err = pa.Hash(buffer)
		if err != nil {
			panic(err)
		}
	}
	return p
}

func (*PointAdapter) Unwrap(p curves.Point) fu.Underlyer {
	return binary.LittleEndian.Uint64(p.ToAffineCompressed()[:8])
}

func (pa *PointAdapter) ZeroValue() curves.Point {
	return pa.AdditiveIdentity()
}

var _ fu.ObjectAdapter[curves.Scalar] = (*ScalarAdapter)(nil)

type ScalarAdapter struct {
	curves.ScalarField
}

func NewScalarAdapter(scalarField curves.ScalarField) fu.ObjectAdapter[curves.Scalar] {
	return &ScalarAdapter{ScalarField: scalarField}
}

func (sa *ScalarAdapter) Wrap(x fu.Underlyer) curves.Scalar {
	buffer := make([]byte, sa.ElementSize())
	binary.LittleEndian.PutUint64(buffer[:8], x)
	s, err := sa.Element().SetBytes(buffer)
	if err != nil {
		s, err = sa.Hash(buffer)
		if err != nil {
			panic(err)
		}
	}
	return s
}

func (*ScalarAdapter) Unwrap(s curves.Scalar) fu.Underlyer {
	return binary.LittleEndian.Uint64(s.Bytes()[:8])
}

func (sa *ScalarAdapter) ZeroValue() curves.Scalar {
	return sa.Zero()
}

var _ fu.ObjectAdapter[curves.BaseFieldElement] = (*BaseFieldElementAdapter)(nil)

type BaseFieldElementAdapter struct {
	curves.BaseField
}

func NewBaseFieldElementAdapter(baseField curves.BaseField) fu.ObjectAdapter[curves.BaseFieldElement] {
	return &BaseFieldElementAdapter{BaseField: baseField}
}

func (ba *BaseFieldElementAdapter) Wrap(x fu.Underlyer) curves.BaseFieldElement {
	buffer := make([]byte, ba.ElementSize())
	binary.LittleEndian.PutUint64(buffer[:8], x)
	f, err := ba.Element().SetBytes(buffer)
	if err != nil {
		f, err = ba.Hash(buffer)
		if err != nil {
			panic(err)
		}
	}
	return f
}

func (*BaseFieldElementAdapter) Unwrap(f curves.BaseFieldElement) fu.Underlyer {
	return binary.LittleEndian.Uint64(f.Bytes()[:8])
}

func (ba *BaseFieldElementAdapter) ZeroValue() curves.BaseFieldElement {
	return ba.Zero()
}
