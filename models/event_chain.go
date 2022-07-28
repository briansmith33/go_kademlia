package models

import (
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"kademlia/utils"
	"strconv"
	"strings"
)

type EventChain struct {
	Head       *Event
	Difficulty int
}

func (ec *EventChain) Mine(event *Event) {
	minInt, maxInt := utils.GetTargetRange(40, ec.Difficulty)
	hashData := append([]byte(event.Data), event.Signature...)
	if event.Prev != nil {
		hashData = append(hashData, []byte(event.Prev.Hash)...)
	} else {
		hashData = append(hashData, []byte(strings.Repeat("0", 40))...)
	}

	nonce := 0
	for {
		hash := sha1.New()
		io.WriteString(hash, string(hashData)+strconv.Itoa(nonce))
		h := binary.BigEndian.Uint64(hash.Sum(nil))
		if minInt < h && h < maxInt {
			event.Hash = hex.EncodeToString(hash.Sum(nil))
			event.Nonce = nonce
			return
		}
		nonce += 1
	}
}

func (ec *EventChain) Append(event *Event) {
	if ec.Head == nil {
		ec.Head = event
		ec.Mine(event)
	} else {
		current := ec.Head
		for {
			if current.Next == nil {
				event.Prev = current
				current.Next = event
				ec.Mine(event)
				return
			}
			current = current.Next
		}
	}
}

func (ec *EventChain) Last() *Event {
	if ec.Head == nil {
		return nil
	}
	current := ec.Head
	for {
		if current.Next == nil {
			return current
		}
		current = current.Next
	}
}

func (ec *EventChain) Print() {
	if ec.Head == nil {
		return
	}
	current := ec.Head
	for {
		fmt.Println(current.Hash)
		if current.Next == nil {
			return
		}
		current = current.Next
	}
}
