package algebra

// ******************** RAlgebra
// === Interfaces

type RAlgebra[A Module[A, UR, AE, S, OpAdd, UOpAdd, UOpMul], UR Rng[UR, S, UOpAdd, UOpMul], AE RAlgebraElement[AE, S], S RngElement[S], OpAdd Addition[AE], OpProd Multiplication[AE], UOpAdd Addition[S], UOpMul Multiplication[S]] interface {
	BiSuperStructure[A, UR, AE, OpAdd, OpProd]
	Module[A, UR, AE, S, OpAdd, UOpAdd, UOpMul]
	MagmaticMultiplicativeness[AE]
}

type RAlgebraElement[AE GroupElement[AE], S RngElement[S]] interface {
	ModuleElement[AE, S]
	MagmaElementalMultiplicativeness[AE]
}

// ******************** Unital Algebra
// === Interfaces

type UnitalAlgebra[A RAlgebra[A, UR, AE, S, OpAdd, OpProd, UOpAdd, UOpMul], UR AbelianRing[UR, S, UOpAdd, UOpMul], AE UnitalAlgebraElement[AE, S], S AbelianRingElement[S], OpAdd Addition[AE], OpProd Multiplication[AE], UOpAdd Addition[S], UOpMul Multiplication[S]] interface {
	RAlgebra[A, UR, AE, S, OpAdd, OpProd, UOpAdd, UOpMul]
	UnitalModule[A, UR, AE, S, OpAdd, UOpAdd, UOpMul]
	MonoidalMultiplicativeness[AE]
}

type UnitalAlgebraElement[AE RAlgebraElement[AE, URE], URE AbelianRingElement[URE]] interface {
	RAlgebraElement[AE, URE]
	UnitalModuleElement[AE, URE]
	MonoidElementalMultiplicativeness[AE]
}

// // ******************** Division Algebra
// // === Interfaces

type DivisionAlgebra[A UnitalAlgebra[A, UF, AE, S, OpAdd, OpProd, UOpAdd, UOpMul], UF AbelianField[UF, S, UOpAdd, UOpMul], AE DivisionAlgebraElement[AE, S], S AbelianFieldElement[S], OpAdd Addition[AE], OpProd Multiplication[AE], UOpAdd Addition[S], UOpMul Multiplication[S]] interface {
	UnitalAlgebra[A, UF, AE, S, OpAdd, OpProd, UOpAdd, UOpMul]
	GroupalMultiplicativeness[AE]
}

type DivisionAlgebraElement[AE UnitalAlgebraElement[AE, UFE], UFE AbelianFieldElement[UFE]] interface {
	UnitalAlgebraElement[AE, UFE]
	GroupElementalMultiplicativeness[AE]
}
