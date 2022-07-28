package models

type Event struct {
	Data      string
	Signature []byte
	Hash      string
	Prev      *Event
	Nonce     int
	Next      *Event
}
