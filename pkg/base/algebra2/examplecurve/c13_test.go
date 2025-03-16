package examplecurve_test

// import (
// 	"fmt"
// 	"github.com/bronlabs/krypton-primitives/pkg/base/algebra2/examplecurve"
// )

// func Example_c13Addition() {
// 	// (4,4) -> (9, 6) -> (9, 7) -> (4, 9) -> inf

// 	g := examplecurve.C13CurveInstance.PrimeSubGroupGenerator()
// 	p := g.Clone()
// 	for i := 0; i < 5; i++ {
// 		fmt.Printf("%s\n", p)
// 		p = p.Op(g)
// 	}

// 	// Output:
// 	// (4, 4, 1)
// 	// (9, 6, 1)
// 	// (9, 7, 1)
// 	// (4, 9, 1)
// 	// (0, 1, 0)
// }
