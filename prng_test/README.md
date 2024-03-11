# PRNG tester

* This is a small application using [TestU01](http://simul.iro.umontreal.ca/testu01/tu01.html) to test pseudo random number generator.

## Implement a test

* Implement the interface `PrngTest` and pass it into `RunPrngTest` to run the test
* `prngs/crand.go` sample code tests golang's `crand/rand` package
* Update main.go to test the new implementation

## Build and run

* `make prng-test`
