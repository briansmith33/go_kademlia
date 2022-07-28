package models

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"kademlia/utils"
	"math"
	"math/rand"
	"time"
)

type RoutingTable struct {
	Head *KBucket `json:"head"`
	K    int      `json:"k"`
}

func (rt *RoutingTable) Len() int {
	length := 0
	current := rt.Head
	for {
		length += 1
		current = current.Next
		if current == rt.Head {
			break
		}
	}
	return length
}

func (rt *RoutingTable) Append(newBucket *KBucket) {
	if rt.Head == nil {
		rt.Head = newBucket
		rt.Head.Next = rt.Head
		rt.Head.Prev = rt.Head
	} else {
		prev := rt.Head.Prev
		rt.Head.Prev = newBucket
		newBucket.Next = rt.Head
		newBucket.Prev = prev
		prev.Next = newBucket
	}
}

func (rt *RoutingTable) Prepend(newBucket *KBucket) {
	if rt.Head == nil {
		newBucket.Next = newBucket
		newBucket.Prev = newBucket
	} else {
		prev := rt.Head.Prev
		rt.Head.Prev = newBucket
		newBucket.Next = rt.Head
		newBucket.Prev = prev
		prev.Next = newBucket
	}
	rt.Head = newBucket
}

func (rt *RoutingTable) AddPeer(newPeer *Peer) {
	bucket := rt.FindClosest(newPeer.ID)
	if bucket == nil {
		bucket = &KBucket{K: 20, Difficulty: 3}
		bucket.Add(newPeer)
		rt.Insert(bucket)
	} else if bucket.Size() < bucket.K {
		bucket.Add(newPeer)
	} else {
		bucket1, bucket2 := bucket.Split()
		rt.DeleteByID(bucket.Root.ID)
		rt.Insert(&bucket1)
		rt.Insert(&bucket2)
		newByteID, _ := hex.DecodeString(newPeer.ID)
		newIntID := binary.BigEndian.Uint64(newByteID)
		firstByteID, _ := hex.DecodeString(bucket1.Root.ID)
		firstIntID := binary.BigEndian.Uint64(firstByteID)
		secondByteID, _ := hex.DecodeString(bucket2.Root.ID)
		secondIntID := binary.BigEndian.Uint64(secondByteID)
		leftDistance := newIntID ^ firstIntID
		rightDistance := newIntID ^ secondIntID
		if leftDistance < rightDistance {
			bucket1.Add(newPeer)
		} else {
			bucket2.Add(newPeer)
		}
	}
}

func (rt *RoutingTable) FindPeer(id string) *Peer {
	bucket := rt.FindClosest(id)
	if bucket != nil {
		peer := bucket.FindNode(id)
		if peer == nil {
			peer = bucket.Prev.FindNode(id)
		}

		if peer == nil {
			peer = bucket.Next.FindNode(id)
		}
		return peer
	}
	return nil
}

func (rt *RoutingTable) Insert(newBucket *KBucket) {
	buckets := rt.List()
	if len(buckets) == 0 {
		rt.Append(newBucket)
		return
	}
	newByteID, _ := hex.DecodeString(newBucket.Root.ID)
	newIntID := binary.BigEndian.Uint64(newByteID)

	firstByteID, _ := hex.DecodeString(buckets[0].Root.ID)
	firstIntID := binary.BigEndian.Uint64(firstByteID)
	if newIntID < firstIntID {
		rt.Prepend(newBucket)
		return
	}
	lastByteID, _ := hex.DecodeString(buckets[len(buckets)-1].Root.ID)
	lastIntID := binary.BigEndian.Uint64(lastByteID)
	if newIntID > lastIntID {
		rt.Append(newBucket)
		return
	}

	for i := 0; i < len(buckets)-1; i++ {
		prevByteID, _ := hex.DecodeString(buckets[i].Root.ID)
		prevIntID := binary.BigEndian.Uint64(prevByteID)
		nextByteID, _ := hex.DecodeString(buckets[i+1].Root.ID)
		nextIntID := binary.BigEndian.Uint64(nextByteID)
		if prevIntID < newIntID && newIntID < nextIntID {
			rt.AddAfterNode(buckets[i].Root.ID, newBucket)
			return
		}
	}
}

func (rt *RoutingTable) AddAfterNode(id string, newBucket *KBucket) {
	current := rt.Head
	for {
		if current.Next == rt.Head && current.Root.ID == id {
			rt.Append(newBucket)
			return
		} else if current.Root.ID == id {
			next := current.Next
			current.Next = newBucket
			newBucket.Next = next
			newBucket.Prev = current
			next.Prev = newBucket
			return
		}
		current = current.Next
	}
}

func (rt *RoutingTable) AddBeforeNode(id string, newBucket *KBucket) {
	current := rt.Head
	for {
		if current.Prev == rt.Head && current.Root.ID == id {
			rt.Prepend(newBucket)
			return
		} else if current.Root.ID == id {
			prev := current.Prev
			prev.Next = newBucket
			current.Prev = newBucket
			newBucket.Next = current
			newBucket.Prev = prev
			return
		}
		current = current.Next
	}
}

func (rt *RoutingTable) DeleteByID(id string) {
	current := rt.Head
	for {
		if current.Root.ID == id && current == rt.Head {
			if current.Next == current {
				rt.Head = nil
			} else {
				next := current.Next
				prev := current.Prev
				prev.Next = next
				next.Prev = prev
				rt.Head = next
			}
			current = nil
			return
		} else if current.Root.ID == id {
			next := current.Next
			prev := current.Prev
			prev.Next = next
			next.Prev = prev
			current = nil
			return
		}
		current = current.Next
		if current == rt.Head {
			return
		}
	}
}

func (rt *RoutingTable) DeleteBucket(bucket *KBucket) {
	current := rt.Head
	for {
		if current == bucket && current == rt.Head {
			if current.Next == current {
				rt.Head = nil
			} else {
				next := current.Next
				prev := current.Prev
				prev.Next = next
				next.Prev = prev
				rt.Head = next
			}
			current = nil
			return
		} else if current == bucket {
			next := current.Next
			prev := current.Prev
			prev.Next = next
			next.Prev = prev
			current = nil
			return
		}
		current = current.Next
		if current == rt.Head {
			return
		}
	}
}

func (rt *RoutingTable) FindBucket(id string) *KBucket {
	current := rt.Head
	if current.Root.ID == id {
		return current
	}
	targetByteID, _ := hex.DecodeString(id)
	targetIntID := binary.BigEndian.Uint64(targetByteID)
	prevByteID, _ := hex.DecodeString(current.Prev.Root.ID)
	prevIntID := binary.BigEndian.Uint64(prevByteID)
	nextByteID, _ := hex.DecodeString(current.Next.Root.ID)
	nextIntID := binary.BigEndian.Uint64(nextByteID)
	leftDistance := prevIntID ^ targetIntID
	rightDistance := nextIntID ^ targetIntID
	if leftDistance < rightDistance {
		for {
			if current.Root.ID == id {
				return current
			}
			current = current.Prev
			if current == rt.Head {
				return nil
			}
		}
	} else {
		for {
			if current.Root.ID == id {
				return current
			}
			current = current.Next
			if current == rt.Head {
				return nil
			}
		}
	}
}

func (rt *RoutingTable) FindClosest(id string) *KBucket {
	if rt.Head == nil {
		return nil
	}
	current := rt.Head
	for {
		targetByteID, _ := hex.DecodeString(id)
		targetIntID := binary.BigEndian.Uint64(targetByteID)
		currentByteID, _ := hex.DecodeString(current.Root.ID)
		currentIntID := binary.BigEndian.Uint64(currentByteID)
		nextByteID, _ := hex.DecodeString(current.Next.Root.ID)
		nextIntID := binary.BigEndian.Uint64(nextByteID)
		leftDistance := currentIntID ^ targetIntID
		rightDistance := nextIntID ^ targetIntID
		if currentIntID < targetIntID && targetIntID < nextIntID {
			if leftDistance < rightDistance {
				return current
			}
			return current.Next
		}
		if current.Next == rt.Head {
			if leftDistance <= rightDistance {
				return current
			}
			return current.Next
		}
		current = current.Next
	}
}

func (rt *RoutingTable) Reverse() {
	var temp *KBucket
	current := rt.Head
	for {
		temp = current.Prev
		current.Prev = current.Next
		current.Next = temp
		current = current.Prev
		if current == rt.Head {
			break
		}
	}
	if temp != nil {
		rt.Head = temp.Prev
	}
}

func Shuffle(peers []*Peer) []*Peer {
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(peers), func(i, j int) {
		peers[i], peers[j] = peers[j], peers[i]
	})
	return peers
}

func (rt *RoutingTable) RemoveDuplicates() {
	current := rt.Head
	var seen []string
	for {
		if !utils.InArray(seen, current.Root.ID) {
			seen = append(seen, current.Root.ID)
			current = current.Next
		} else {
			next := current.Next
			rt.DeleteBucket(current)
			current = next
		}
		if current == rt.Head {
			return
		}
	}
}

func (rt *RoutingTable) Split() *RoutingTable {
	size := rt.Len()
	if size == 0 {
		return nil
	}
	if size == 1 {
		return rt
	}
	mid := int(math.Floor(float64(size / 2)))
	count := 0
	var prev *KBucket
	current := rt.Head
	for count < mid {
		count += 1
		prev = current
		current = current.Next
	}
	prev.Next = rt.Head
	split := RoutingTable{K: 20}
	for current.Next != rt.Head {
		bucket := KBucket{K: 20, Difficulty: 3}
		for _, peer := range current.PreOrder() {
			bucket.Add(peer)
		}

		split.Append(&bucket)
		current = current.Next
	}
	bucket := KBucket{K: 20, Difficulty: 3}
	for _, peer := range current.PreOrder() {
		bucket.Add(peer)
	}
	split.Append(&bucket)
	return &split
}

func partition(peers []*Peer, start int, end int) int {
	i := start + 1
	piv := peers[start]
	j := start + 1
	for j <= end {
		if peers[i].ID < piv.ID {
			peers[i], peers[j] = peers[j], peers[i]
			i += 1
		}
		j += 1
	}
	peers[start], peers[i-1] = peers[i-1], peers[start]
	return i - 1
}

func quickSort(peers []*Peer, start int, end int) []*Peer {
	if start < end {
		pivPos := partition(peers, start, end)
		quickSort(peers, start, pivPos-1)
		quickSort(peers, pivPos+1, end)
	}
	return peers
}

func (rt *RoutingTable) Sort() RoutingTable {
	var peers []*Peer
	current := rt.Head
	for {
		for _, peer := range current.InOrder() {
			peers = append(peers, peer)
		}
		current = current.Next
		if current == rt.Head {
			break
		}
	}
	peers = quickSort(peers, 0, len(peers)-1)

	table := RoutingTable{K: 20}
	for i := 0; i < len(peers); i += rt.K {
		chunk := peers[i : i+rt.K]
		chunk = Shuffle(chunk)
		bucket := KBucket{K: 20, Difficulty: 3}
		for _, peer := range chunk {
			bucket.Add(peer.Copy())
		}
		table.Append(&bucket)
	}
	return table
}

func (rt *RoutingTable) Josephus(step int) {
	current := rt.Head
	for rt.Len() > 1 {
		count := 1
		for count != step {
			current = current.Next
			count += 1
		}
		rt.DeleteByID(current.Root.ID)
		current = current.Next
	}
}

func (rt *RoutingTable) IsCircular(inputList *RoutingTable) bool {
	current := rt.Head
	for current.Next != nil {
		current = current.Next
		if current.Next == rt.Head {
			return true
		}
	}
	return false
}

func (rt *RoutingTable) List() []*KBucket {
	var buckets []*KBucket
	current := rt.Head
	if current == nil {
		return buckets
	}
	for {
		buckets = append(buckets, current)
		current = current.Next
		if current == rt.Head {
			return buckets
		}
	}
}

func (rt *RoutingTable) ListPeers() []*Peer {
	var peers []*Peer
	current := rt.Head
	for {
		for _, peer := range current.InOrder() {
			peers = append(peers, peer)
		}
		current = current.Next
		if current == rt.Head {
			break
		}
	}
	return peers
}

func (rt *RoutingTable) AsTuples() []Tuple {
	current := rt.Head
	var tuples []Tuple
	for {
		for _, peer := range current.PreOrder() {
			tuples = append(tuples, peer.AsTuple())
		}
		current = current.Next
		if current == rt.Head {
			break
		}
	}
	return tuples
}

func (rt *RoutingTable) PrintList() {
	current := rt.Head
	for {
		fmt.Println(current.Root.ID)
		current = current.Next
		if current == rt.Head {
			break
		}
	}
}
