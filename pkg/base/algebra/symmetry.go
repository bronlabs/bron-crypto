package algebra

var _ Group[any, AutoFunction[any]] = (*SymmetricGroup[any, Set[any], any, any])(nil)

type SymmetricGroup[G Structure, Obj Set[ObjE], E, ObjE Element] struct {
	FiniteStructure
	Aut[G, ObjE]
}
