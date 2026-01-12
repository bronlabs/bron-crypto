# kmac

KMAC (Keccak Message Authentication Code) implementation per [NIST SP 800-185](https://csrc.nist.gov/publications/detail/sp/800-185/final).

## Usage

```go
h, err := kmac.NewKMAC256(key, 32, []byte("my-domain"))
if err != nil {
    return err
}
h.Write(message)
tag := h.Sum(nil)
```
