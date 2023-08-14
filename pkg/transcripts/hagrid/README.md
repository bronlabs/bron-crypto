
# Hagrid Transcript

This package implements a transcript functionality and transcript-based PRNG.

### Transcript

Transcript is inspired by gtank/merlin, but is not a fork. It is modified for our own purposes.
* The initial state is a hash of the protocol name
* Appending a message is done by hashing previous state and the message
* ExtractBytes with output size is done by hashing the state with Cshake

### Transcript-based PRNG

A transcript-based PRNG is a pseudorandom number generator that uses the transcript as a source of randomness, ensuring that the output is unpredictable and bound to the protocol execution.

## Usage

```go
// Create a new transcript
t := NewTranscript("protocol_name")
// Append a message
t.AppendMessage("message label", []byte("message"))
// Extract bytes
t.ExtractBytes("output label", 32)

// Create a new transcript-based PRNG
r, err := t1.NewReader("witness", []byte("secret seed"), crand.Reader)
// generate random bytes
s1 = make([]byte, 32)
r1.Read(s1)
```

