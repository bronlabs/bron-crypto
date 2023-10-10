## Tests

Ideally, each package should have the following tests:
* Unit tests: Test the logics
* Benchmark tests: Test performance
* Fuzz tests: Discover corner cases
* Constant time tests: Test if a function is constant time
* Profiling tests: Test cpu and memory usage

To run all those tests for a specific package, you can run:
```bash
make test-package-...
```
for example:
```
make test-package-hashing
```

## Implement a Benchmark Test

* Benchmark test is to test performance of a function.
* Template:
```go
func Benchmark...(b *testing.B) {
  b.Run("test name...", func(b *testing.B) {
    for n := 0; n < b.N; n++ {
      ...
    }
  }
})
```

## Implement a Profile Test

* This test is quite similar to a unit test.
* Profile tests should be in a separate test file `*_profile_test.go`
* Make sure the test name is always `TestRunProfile` so it would be easier to automate the test.
* It wraps a happy path of a unit tests and repeat the test many times. We use a special syntax running the test to record cpu and memory usage for analysing.
* Because there is no separate between profile and unit test in golang, we often have this at start of each profile test to make sure that it does not run together with other unit tests. For example:
```go
func TestRunProfile(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping profiling test in short mode")
	}
	if os.Getenv("PROFILE_TEST") == "" {
		t.Skip("skipping non profiling test")
	}
	for i := 0; i < 1000; i++ {
		testHappyPath()
	}
}
```

## Implement a Fuzz Test

* The recommended approach is to create a fuzz package within the package you want to test, and then add a fuzz_test.go file to that package. This file should contain the fuzz tests you want to run.
* A fuzzing function template looks like this:

```go
func Fuzz_Test_...(f *testing.F) {
 f.Add(...)
 f.Fuzz(func(t *testing.T, paramA []byte, paramB int) {
  ...
 })
}
```

* Please make name always start with `Fuzz_`, so it will be easier to automate the test.
* Line `f.Add(...)` is to help golang's fuzz engine better estimate the coverage, so please add a few example parameter to help it to cover the code. Normally, we use f.Add to add all possible happy path cases.
* The `f.Fuzz` line runs the function with randomly generated parameters`paramA` and `paramB`
* The way we write fuzzing functions is similar to unit tests, except that in unit tests all errors are bad, while in fuzzing functions we only want to catch bad errors and ignore good errors. Generally, bad errors are the ones that we do not handle. (You can use `errors.IsKnownError(err)` to check if an error is known or not).
* If it is a good error, we don’t want the fuzzing engine to explore that case, so we can tell it to skip the case by using `f.Skip()`
