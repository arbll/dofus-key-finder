package decrypt

import (
	"bytes"
	"testing"
)

func TestChecksumRotationRoundTrip(t *testing.T) {
	for _, key := range [][]byte{nil, []byte("a"), []byte("A%+xyz"), bytes.Repeat([]byte("Qz%+!"), 33)} {
		if got := Unrotate(Rotate(key)); !bytes.Equal(got, key) {
			t.Fatalf("rotation round trip: got %q want %q", got, key)
		}
	}
	// Independent formula, including a shift larger than the key length.
	key := []byte{33, 34, 36} // sum=103; shift=14; 14%3=2
	if got := Rotate(key); !bytes.Equal(got, []byte{36, 33, 34}) {
		t.Fatalf("rotation: %v", got)
	}
}
