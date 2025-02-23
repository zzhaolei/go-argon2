package argon2

/*
#cgo CFLAGS: -w
#cgo CFLAGS: -I./argon2/include -I./argon2/src/blake2
#include "argon2/src/argon2.c"
#include "argon2/src/core.c"
#include "argon2/src/blake2/blake2b.c"
#include "argon2/src/thread.c"
#include "argon2/src/encoding.c"
#include "argon2/src/ref.c"
*/
import "C"
import (
	"encoding/hex"
	"fmt"
	"runtime"
	"unsafe"
)

const (
	Version10 = 0x10
	Version13 = 0x13
)

const (
	Argon2d = iota
	Argon2i
	Argon2id
)

func Hash(mode, version int, password, salt []byte, time, memory uint32, threads uint8, hashLen int) (string, error) {
	var ctx C.argon2_context

	hash := make([]byte, hashLen)

	var pinner runtime.Pinner
	defer pinner.Unpin()

	pinner.Pin(unsafe.Pointer(&password[0]))
	pinner.Pin(unsafe.Pointer(&hash[0]))
	pinner.Pin(unsafe.Pointer(&salt[0]))

	ctx.outlen = C.uint32_t(hashLen)
	ctx.out = (*C.uint8_t)(&hash[0])

	ctx.pwd = (*C.uint8_t)(&password[0])
	ctx.pwdlen = C.uint32_t(len(password))

	ctx.salt = (*C.uint8_t)(&salt[0])
	ctx.saltlen = C.uint32_t(len(salt))

	ctx.secret = (*C.uint8_t)(nil)
	ctx.secretlen = 0

	ctx.ad = (*C.uint8_t)(nil)
	ctx.adlen = 0

	ctx.allocate_cbk = nil
	ctx.free_cbk = nil

	ctx.flags = C.uint32_t(C.ARGON2_DEFAULT_FLAGS)

	ctx.t_cost = C.uint32_t(time)
	ctx.m_cost = C.uint32_t(memory)
	ctx.lanes = C.uint32_t(threads)
	ctx.threads = C.uint32_t(threads)

	ctx.version = C.uint32_t(version)

	result := C.argon2_ctx(&ctx, C.argon2_type(mode))
	if result != C.ARGON2_OK {
		// TODO - define errors
		return "", fmt.Errorf("argon2 error: %v", result)
	}
	return hex.EncodeToString(hash), nil
}
