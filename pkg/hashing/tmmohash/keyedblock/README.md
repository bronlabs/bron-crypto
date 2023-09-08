# Fixed AES
This package is a fork of selected pieces from golang's `crypto/aes` package, modified to expose the `expandKeyAsm` internal function via a `SetKey` member function of `AesCipherAsm`. 

In the tmmohash the keys change at each iteration. The `crypto/aes` package forces an allocation of a struct for each key refresh, incurring in a high overhead for use-cases such as that of tmmohash. By maintaining the same initialized memory throughout multiple key expansions, this package makes the process of `expansion -> encrypt` **seven times faster** than by using classical golang.