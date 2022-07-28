package models

import (
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"kademlia/utils"
	"math"
	"strconv"
)

// KBucket ...
type KBucket struct {
	Root       *Peer    `json:"root"`
	Next       *KBucket `json:"next"`
	Prev       *KBucket `json:"prev"`
	K          int      `json:"k"`
	Difficulty int      `json:"difficulty"`
}

func (kb *KBucket) Add(new_peer *Peer) {
	kb.add(new_peer, kb.Root)
}

func (kb *KBucket) add(new_peer *Peer, current *Peer) {
	if kb.Root == nil {
		kb.Root = new_peer
	} else {
		if new_peer.ID < current.ID {
			if current.Left == nil {
				current.Left = new_peer
			} else {
				kb.add(new_peer, current.Left)
			}
		} else {
			if current.Right == nil {
				current.Right = new_peer
			} else {
				kb.add(new_peer, current.Right)
			}
		}
	}
}

func (kb *KBucket) Delete(id string) *Peer {
	return kb.delete(id, kb.Root)
}

func (kb *KBucket) delete(id string, current *Peer) *Peer {
	targetByteID, _ := hex.DecodeString(id)
	targetIntID := binary.BigEndian.Uint64(targetByteID)
	currentByteID, _ := hex.DecodeString(current.ID)
	currentIntID := binary.BigEndian.Uint64(currentByteID)
	if targetIntID < currentIntID {
		current.Left = kb.delete(id, current.Left)
	} else if targetIntID > currentIntID {
		current.Right = kb.delete(id, current.Right)
	} else {
		if current.Left == nil {
			return current.Right
		} else if current.Right == nil {
			return current.Left
		} else {
			temp := kb.min(current.Right)
			current.ID = temp.ID
			current.Right = kb.delete(temp.ID, current.Right)
		}
	}
	return current
}

func (kb *KBucket) FindNode(id string) *Peer {
	if kb.Root == nil {
		return nil
	}
	return kb.findNode(id, kb.Root)
}

func (kb *KBucket) findNode(id string, current *Peer) *Peer {
	targetByteID, _ := hex.DecodeString(id)
	targetIntID := binary.BigEndian.Uint64(targetByteID)
	currentByteID, _ := hex.DecodeString(current.ID)
	currentIntID := binary.BigEndian.Uint64(currentByteID)
	if targetIntID < currentIntID {
		if current.Left == nil {
			return nil
		}
		return kb.findNode(id, current.Left)
	} else if targetIntID > currentIntID {
		if current.Right == nil {
			return nil
		}
		return kb.findNode(id, current.Right)
	} else {
		return current
	}
}

func (kb *KBucket) FindClosest(id string) Peer {
	var closest Peer
	distance := math.Inf(1)
	kb.findClosest(id, &closest, &distance, kb.Root)
	return closest
}

func (kb *KBucket) findClosest(id string, closest *Peer, distance *float64, current *Peer) {
	targetByteID, _ := hex.DecodeString(id)
	targetIntID := binary.BigEndian.Uint64(targetByteID)
	currentByteID, _ := hex.DecodeString(current.ID)
	currentIntID := binary.BigEndian.Uint64(currentByteID)
	if *distance > float64(targetIntID^currentIntID) {
		*distance = float64(targetIntID ^ currentIntID)
		*closest = *current
	}

	if current.Left != nil {
		kb.findClosest(id, closest, distance, current.Left)
	}

	if current.Right != nil {
		kb.findClosest(id, closest, distance, current.Right)
	}
}

func (kb *KBucket) FindAClosest(id string, a int) []*Peer {
	var bucketIDS []string
	for _, peer := range kb.InOrder() {
		bucketIDS = append(bucketIDS, peer.ID)
	}
	targetByteID, _ := hex.DecodeString(id)
	targetIntID := binary.BigEndian.Uint64(targetByteID)
	var aClosest []*Peer
	for i := 0; i < a; i++ {
		if len(bucketIDS) > 0 {
			closestIndex := 0
			closestDistance := math.Inf(1)
			for j, peerID := range bucketIDS {
				currentByteID, _ := hex.DecodeString(peerID)
				currentIntID := binary.BigEndian.Uint64(currentByteID)
				distance := float64(targetIntID ^ currentIntID)
				if distance < closestDistance {
					closestIndex = j
					closestDistance = distance
				}
			}
			aClosest = append(aClosest, kb.FindNode(bucketIDS[closestIndex]))
			bucketIDS = append(bucketIDS[:closestIndex], bucketIDS[closestIndex+1:]...)
		}
	}
	return aClosest
}

func (kb *KBucket) Min() *Peer {
	return kb.min(kb.Root)
}

func (kb *KBucket) min(current *Peer) *Peer {
	if current.Left != nil {
		return kb.min(current.Left)
	}
	return current
}

func (kb *KBucket) Max() *Peer {
	return kb.max(kb.Root)
}

func (kb *KBucket) max(current *Peer) *Peer {
	if current.Right != nil {
		return kb.max(current.Right)
	}
	return current
}

func (kb *KBucket) Height() float64 {
	return kb.height(kb.Root)
}

func (kb *KBucket) height(current *Peer) float64 {
	if current == nil {
		return -1
	}
	leftHeight := kb.height(current.Left)
	rightHeight := kb.height(current.Right)
	return 1 + math.Max(leftHeight, rightHeight)
}

func (kb *KBucket) Size() int {
	if kb.Root == nil {
		return 0
	}

	stack := Stack{}
	stack.Push(kb.Root)
	size := 1
	for !stack.IsEmpty() {
		node := stack.Pop()
		if node.Left != nil {
			size += 1
			stack.Push(node.Left)
		}
		if node.Right != nil {
			size += 1
			stack.Push(node.Right)
		}
	}
	return size
}

func (kb *KBucket) Split() (KBucket, KBucket) {
	peers := kb.InOrder()
	k1 := KBucket{K: kb.K, Difficulty: kb.Difficulty}
	first := Shuffle(peers[0:int(math.Floor(float64(len(peers)/2)))])
	for _, peer := range first {
		k1.Add(peer.Copy())
	}
	k2 := KBucket{K: kb.K, Difficulty: kb.Difficulty}
	second := Shuffle(peers[int(math.Floor(float64(len(peers)/2))):len(peers)])
	for _, peer := range second {
		k2.Add(peer.Copy())
	}
	return k1, k2
}

func (kb *KBucket) PreOrder() []*Peer {
	peerList := []*Peer{}
	kb.preOrder(&peerList, kb.Root)
	return peerList
}

func (kb *KBucket) preOrder(peerList *[]*Peer, current *Peer) {
	*peerList = append(*peerList, current)
	if current.Left != nil {
		kb.preOrder(peerList, current.Left)
	}
	if current.Right != nil {
		kb.preOrder(peerList, current.Right)
	}
}

func (kb *KBucket) InOrder() []*Peer {
	peerList := []*Peer{}
	kb.inOrder(&peerList, kb.Root)
	return peerList
}

func (kb *KBucket) inOrder(peerList *[]*Peer, current *Peer) {
	if current.Left != nil {
		kb.inOrder(peerList, current.Left)
	}
	*peerList = append(*peerList, current)
	if current.Right != nil {
		kb.inOrder(peerList, current.Right)
	}
}

func (kb *KBucket) PostOrder() []*Peer {
	peerList := []*Peer{}
	kb.postOrder(&peerList, kb.Root)
	return peerList
}

func (kb *KBucket) postOrder(peerList *[]*Peer, current *Peer) {
	if current.Left != nil {
		kb.postOrder(peerList, current.Left)
	}
	if current.Right != nil {
		kb.postOrder(peerList, current.Right)
	}
	*peerList = append(*peerList, current)
}

func (kb *KBucket) MerkleRoot() string {
	var leaves []string
	for _, peer := range kb.InOrder() {
		leaves = append(leaves, peer.ID)
	}
	for len(leaves) > 1 {
		if len(leaves)&1 == 1 {
			leaves = append(leaves, leaves[len(leaves)-1])
		}
		var newLeaves []string
		for i := 0; i < len(leaves); i += 2 {
			h := sha1.New()
			io.WriteString(h, leaves[i]+leaves[i+1])
			leaf := fmt.Sprintf("%x", h.Sum(nil))
			newLeaves = append(newLeaves, leaf)
		}
		leaves = newLeaves
	}
	return leaves[0]
}

func (kb *KBucket) CalculateNonce() int {
	minInt, maxInt := utils.GetTargetRange(len(kb.Root.ID), kb.Difficulty)
	root := kb.MerkleRoot()
	nonce := 0
	for {
		hash := sha1.New()
		io.WriteString(hash, root+strconv.Itoa(nonce))
		h := binary.BigEndian.Uint64(hash.Sum(nil))
		if minInt < h && h < maxInt {
			return nonce
		}
		nonce += 1
	}
}

func (kb *KBucket) AsTuples() []Tuple {
	var tuples []Tuple
	for _, peer := range kb.PreOrder() {
		tuples = append(tuples, peer.AsTuple())
	}
	return tuples
}
