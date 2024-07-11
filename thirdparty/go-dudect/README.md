# go-dudect

This is a toy implementation in Go of [Dudect](https://github.com/oreparaz/dudect), almost directly translated from C.

Its only purpose is to play around with the DecryptOAEP function to see if the signal caused by the leftPad timing discrepancies is enough to leak being given DecryptOAEP noise. Long story, short: no it doesn't. So Manger's attack would not apply there, unless someone finds another detectable discprancy or a better distinguisher, of course.  (Note that Dudect's aim isn't to be a distinguisher, just to assess the existence of a timing leak and that it's not because it didn't find one there isn't one. The same applies here.)

[dudect.go](dudect.go) ideas' and design's are coming from Oscar Reparaz, Josep Balasch and Ingrid Verbauwhede, all credit goes to them.

## To use it with your code

Simply write a file containing your function, a `func prepare_inputs() (input_data [][]byte, classes []int)` function returning the input data and its classes and a `func do_one_computation(data []byte)` function using your function on the given input, then do a `make filename`, _et voilà_ you can try it with your Go code, natively without having to use any kind of wrapper in C or whatever.

## How does it work?
It tests executables in a black-box setup and does not need to instrument the said executables in anyway. 

Now regarding how it actually works, firstly `dudect` needs two different input data classes of inputs.
It then repeatedly measures the execution time, also called "traces", of the function under study on inputs belonging to the two classes.  (See below.)
`dudect` then performs post-processing on the measurements prior to their statistical analysis. 
It implements two different post-processing procedures: it crops the measurement on each percentiles and processes these cropped data, because timing distributions usually appear to be skewed toward larger execution times; it also performs the statistical analysis on the whole set of data, just in case. Note that only the maximal `t`-value is reported to the user. 

`dudect` leverages Welch's `t`-test to perform statistical analysis on the sampled data. The usage of Welch's `t`-test in the side-channel community has been initiated by Cryptography Research Inc. in 2011.
The goal of this statistical analysis is to disprove the null hypothesis "the two timing distributions are equal", which is the same as saying "this code seems to run in constant time". 
For large samples a `t`-value of `5` or more can be considered sufficient evidence of a timing leak, while a value of `100` or more is an overwhelming evidence (cf. Dudect's paper).

A typical output of the `dudect` test goes as follows:
```
 21/50: meas:  0.06 M, max t(39): +1.90, max tau: 3.17e-05, 
       (5/tau)^2:  2.49e+10,    m.time (ms): 156.79
 INFO:  For the moment, maybe constant time.
```
where the `meas` value represents the number of measurements performed. The `max t(39)` is the maximum `t`-value found and the percentile at which we cropped the data--if any--to get that value. The `max tau` is a `t`-value normalized by the number of measurements, so that one may compare `max tau` values taken with different numbers of measurements. Finally the `(5/tau)^2` value tells us how many measurements we would need to detect an eventual leak, if we aim for a `t`-value of `5`.

## Classes definition

As explained in dudect's paper, this leakage detection method requires two sets of traces for two different input data classes, and we are interested by their respective distributions.  

In order to detect timing leaks, there are various ways to define those input data classes:  
One of these ways that is known to detect many different potential leaks consists in the **fixed-vs-random** `t`-tests (cf. Dudect's paper or Goodwill _et al._ "A testing methodology for side-channel resistance validation"), where one class is fixed to a constant value, while the input data in the second class is picked at random.  

A second method to construct the data set, allowing us to detect timing leaks with less false-positive than the fixed-vs-random case, is the so called **semi-fixed-vs-random** `t`-tests (see Schneider & Moradi "Leakage Assessment Methodology - a clear roadmap for side-channel evaluations"), where we choose the inputs for a class such that a certain intermediate value is obtained.  
Certain inputs are known to force certain rare behaviours, which may leak sensitive information if they are not seemingly constant-time. (See Jaffe _et al._ "Efficient side-channel testing for public key algorithms: RSA case study").

Note again that a positive results in any of the `t`-tests does not imply it is possible to efficiently distinguish the computations and directly perform any sort of timing attacks.
It simply informs us that the code seems to not run in constant time, but it necessitates further, manual, analysis to lead to any meaningful result.
