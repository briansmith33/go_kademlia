package models

import (
	"net"
)

type Tuple struct {
	Addr       *net.UDPAddr
	Difficulty int
}
