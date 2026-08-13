package crypto

// Wipe overwrites b with zeros in place. This is defense-in-depth, not a
// guarantee: Go's runtime/GC can have already copied the underlying bytes
// elsewhere (stack growth, moving collector internals) before Wipe runs,
// and the compiler is in principle free to elide a write nothing reads
// again afterward — the volatile-write tricks that fully close that gap
// need cgo and memory allocated outside the Go heap, which is out of
// scope here. What this DOES meaningfully do is shrink the window during
// which a plaintext secret or a symmetric key sits at a fixed, findable
// address after its owner is done with it, instead of lingering until the
// next GC cycle happens to reclaim it.
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
