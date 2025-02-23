# go-argon2

> An experiment.

1. `go get github.com/zzhaolei/go-argon2`
2. `git clone --recursive https://github.com/zzhaolei/go-argon2.git ./argon2`
3. change `go.mod`, to add `replace github.com/zzhaolei/go-argon2 => ./argon2`

```go
package main

import (
	"fmt"

	"github.com/zzhaolei/go-argon2"
)

func main() {
	got, err := argon2.Hash(argon2.Argon2i, argon2.Version10, []byte("mypassword"), []byte("mysalt-abcdef"), 2, 1<<16, 1, 32)
	if err != nil {
		panic(err)
	}
	fmt.Println(got)
}
```
