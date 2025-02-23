package argon2

import (
	"testing"
)

func TestHash(t *testing.T) {
	got, err := Hash(Argon2i, Version10, []byte("mypassword"), []byte("mysalt-abcdef"), 2, 1<<16, 1, 32)
	if err != nil {
		panic(err)
	}

	want := "2c6c28c69164aded84cfbe025eb27404babb2d27afaadf7ac44c8dee6be041e8"
	if got != want {
		t.Fatalf("want %s, got %s", want, got)
	}
}
