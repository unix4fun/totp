package totp

import (
	"hash"
	"time"

	// external
	"github.com/unix4fun/hotp"
)

const (
	T0      = 0
	Version = "0.1.0"
)

type Totp struct {
	h *hotp.Hotp
	s uint64 // the infamous timestep, default to 30 seconds
}

func New(f func() hash.Hash, s []byte, d int, step int) *Totp {
	t := &Totp{
		h: hotp.New(f, s, d),
		s: uint64(step),
	}
	return t
}

func (t *Totp) GetNow() (uint32, error) {
	now := time.Now().Unix()
	// XXX might need to math.Floor() that value..
	c := uint64(now-T0) / t.s
	return t.h.Get(c)
}

func (t *Totp) Get(time uint64) (uint32, error) {
	c := uint64(time-T0) / t.s
	return t.h.Get(c)
}
