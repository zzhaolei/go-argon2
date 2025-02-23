package argon2

import "fmt"

func ExampleHash() {
	hash, err := Hash(Argon2i, Version10, []byte("mypassword"), []byte("mysalt-abcdef"), 2, 1<<16, 2, 32)
	if err != nil {
		panic(err)
	}

	fmt.Println(hash)
}
