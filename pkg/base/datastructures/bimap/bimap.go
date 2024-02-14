package bimap

import (
	"encoding/json"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

type BiMap[L any, R any] struct {
	left  ds.HashMap[L, R]
	right ds.HashMap[R, L]
}

func NewBiMap[L any, R any](emptyLeft ds.HashMap[L, R], emptyRight ds.HashMap[R, L]) (ds.BiMap[L, R], error) {
	if !emptyLeft.IsEmpty() {
		return nil, errs.NewSize("left is not empty")
	}
	if !emptyRight.IsEmpty() {
		return nil, errs.NewSize("right is not empty")
	}
	return &BiMap[L, R]{
		left:  emptyLeft,
		right: emptyRight,
	}, nil
}

func (m *BiMap[L, R]) LookUpLeft(l L) (R, bool) {
	return m.left.Get(l)
}

func (m *BiMap[L, R]) LookUpRight(r R) (L, bool) {
	return m.right.Get(r)
}

func (m *BiMap[L, R]) LookUp(l L, r R) bool {
	_, leftExists := m.LookUpLeft(l)
	_, rightExists := m.LookUpRight(r)
	return leftExists && rightExists
}

func (m *BiMap[L, R]) Put(l L, r R) {
	_, _, _ = m.TryPut(l, r)
}

func (m *BiMap[L, R]) TryPut(l L, r R) (replaced bool, oldLeft L, oldRight R) {
	replaced, oldRight = m.left.TryPut(l, r)
	_, oldLeft = m.right.TryPut(r, l)
	return replaced, oldLeft, oldRight
}

func (m *BiMap[_, _]) Clear() {
	m.left.Clear()
	m.right.Clear()
}

func (m *BiMap[_, _]) Size() int {
	return m.left.Size()
}

func (m *BiMap[_, _]) IsEmpty() bool {
	return m.left.IsEmpty()
}

func (m *BiMap[L, R]) Remove(l L, r R) {
	_ = m.TryRemove(l, r)
}

func (m *BiMap[L, R]) TryRemove(l L, r R) (removed bool) {
	removed, _ = m.TryRemoveLeft(l)
	_, _ = m.TryRemoveRight(r)
	return removed
}

func (m *BiMap[L, R]) RemoveLeft(l L) {
	_, _ = m.TryRemoveLeft(l)
}

func (m *BiMap[L, R]) TryRemoveLeft(l L) (removed bool, r R) {
	removed, r = m.left.TryRemove(l)
	return removed, r
}

func (m *BiMap[L, R]) RemoveRight(r R) {
	_, _ = m.TryRemoveRight(r)
}

func (m *BiMap[L, R]) TryRemoveRight(r R) (removed bool, l L) {
	removed, l = m.right.TryRemove(r)
	return removed, l
}

func (m *BiMap[L, _]) Left() []L {
	return m.left.Keys()
}

func (m *BiMap[_, R]) Right() []R {
	return m.right.Keys()
}

func (m *BiMap[L, R]) Iter() <-chan ds.LeftRight[L, R] {
	ch := make(chan ds.LeftRight[L, R], 1)
	go func() {
		defer close(ch)
		for pair := range m.left.Iter() {
			ch <- ds.LeftRight[L, R]{
				Left:  pair.Key,
				Right: pair.Value,
			}
		}
	}()
	return ch
}

func (m *BiMap[L, R]) Clone() ds.BiMap[L, R] {
	return &BiMap[L, R]{
		left:  m.CloneLeft(),
		right: m.CloneRight(),
	}
}

func (m *BiMap[L, R]) CloneLeft() ds.HashMap[L, R] {
	return m.left.Clone()
}

func (m *BiMap[L, R]) CloneRight() ds.HashMap[R, L] {
	return m.right.Clone()
}

func (m *BiMap[L, R]) MarshalJSON() ([]byte, error) {
	type temp struct {
		Left  json.RawMessage
		Right json.RawMessage
	}
	leftJson, err := m.left.MarshalJSON()
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not marshal left")
	}
	rightJson, err := m.right.MarshalJSON()
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not marshal right")
	}
	x := &temp{
		Left:  leftJson,
		Right: rightJson,
	}
	serialised, err := json.Marshal(x)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not json marshal")
	}
	return serialised, nil
}
