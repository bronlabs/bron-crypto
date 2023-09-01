
# Hagrid Transcript

This package implements a transcript functionality.

### Transcript

Transcript is inspired by gtank/merlin, but is not a fork. It is modified for our own purposes.
* The initial state is a hash of the protocol name
* Appending a message is done by hashing previous state and the message
* ExtractBytes with output size is done by hashing the state with Cshake

## Usage

```go
// Create a new transcript
t := NewTranscript("protocol_name")
// Append a message
t.AppendMessage("message label", []byte("message"))
// Extract bytes
t.ExtractBytes("output label", 32)
```

