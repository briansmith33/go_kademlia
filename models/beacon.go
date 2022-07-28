package models

import (
	"crypto/ed25519"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github/briansmith33/kademlia/constants"
	"io"
	"kademlia/utils"
	"math/big"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"
)

type Server struct {
	Conn       *net.UDPConn
	Addr       *net.UDPAddr
	BootAddr   *net.UDPAddr
	Table      RoutingTable
	Events     EventChain
	ID         string
	PubKey     ed25519.PublicKey
	Comm       bool
	Generator  *big.Int
	Difficulty int
	A          int
}

func (s *Server) generatePrivateKey() *big.Int {
	priv_key := make([]byte, constants.KEY_LENGTH)
	_, err := rand.Read(priv_key)
	utils.CheckError(err)
	return new(big.Int).SetBytes(priv_key)
}

func (s *Server) generatePublicKey(prime *big.Int, privKey *big.Int) *big.Int {
	var pub_key big.Int
	pub_key.Exp(s.Generator, privKey, prime)
	return &pub_key
}

func (s *Server) getKey(prime *big.Int, privKey *big.Int, remote_pub_key *big.Int) []byte {
	var shared_secret big.Int
	shared_secret.Exp(remote_pub_key, privKey, prime)
	hash := sha256.New()
	hash.Write(shared_secret.Bytes())
	md := hash.Sum(nil)
	return md
}

func (s *Server) AsTuple() Tuple {
	return Tuple{Addr: s.Addr, Difficulty: s.Difficulty}
}

func (s *Server) GetKey() []byte {
	var msg string
	var addr net.Addr
	for {
		chunk := make([]byte, constants.BUFFER)
		var err error
		_, addr, err = s.Conn.ReadFromUDP(chunk)
		utils.CheckError(err)
		msg += strings.TrimSpace(string(chunk))
		if strings.Contains(msg, "<EOF>") {
			break
		}
	}

	msg = strings.Replace(msg, "<EOF>", "", -1)
	message, _ := base64.StdEncoding.DecodeString(msg)
	var offer KeyOffer
	err := json.Unmarshal(message, &offer)
	utils.CheckError(err)
	if offer.Type == "key exchange" && offer.Prime.BitLen() == 2048 {
		hash := sha1.New()
		io.WriteString(hash, addr.(*net.UDPAddr).IP.String())
		peerID := hex.EncodeToString(hash.Sum(nil))
		peer := s.Table.FindPeer(peerID)
		if peer == nil {

			peer = &Peer{
				ID:         peerID,
				Addr:       addr.(*net.UDPAddr),
				Difficulty: 3,
				Generator:  big.NewInt(5),
			}
		}

		minInt, maxInt := utils.GetTargetRange(len(s.ID), peer.Difficulty)
		hash = sha1.New()
		io.WriteString(hash, s.ID+strconv.Itoa(offer.Nonce))
		h := binary.BigEndian.Uint64(hash.Sum(nil))
		if minInt < h && h < maxInt {
			privKey := s.generatePrivateKey()
			pubKey := s.generatePublicKey(offer.Prime, privKey)
			response := KeyOffer{Key: pubKey}
			data, err := json.Marshal(response)
			utils.CheckError(err)
			b64 := base64.StdEncoding.EncodeToString(data)
			msg := b64 + "<EOF>"
			s.Conn.WriteTo([]byte(msg), addr)
			return s.getKey(offer.Prime, privKey, offer.Key)
		}
	}
	return nil
}

func (s *Server) Send(addr *net.UDPAddr, key []byte, msgType string, msgData []byte) {
	msg := Msg{Type: msgType, Data: msgData}
	marshalledMsg, err := json.Marshal(msg)
	utils.CheckError(err)
	encrypted_data := utils.Encrypt(marshalledMsg, key)
	s.Conn.WriteTo([]byte(encrypted_data+"<EOF>"), addr)
}

func (s *Server) Receive(key []byte) (string, []byte, *net.UDPAddr, error) {
	var msg string
	var addr net.Addr
	var err error
	for {
		chunk := make([]byte, constants.BUFFER)
		_, addr, err = s.Conn.ReadFromUDP(chunk)
		msg += strings.TrimSpace(string(chunk))
		if strings.Contains(msg, "<EOF>") {
			break
		}
	}
	msg = strings.Replace(msg, "<EOF>", "", -1)
	decrypted := utils.Decrypt(msg, key)
	var jsonData Msg
	json.Unmarshal([]byte(decrypted), &jsonData)
	return jsonData.Type, jsonData.Data, addr.(*net.UDPAddr), err
}

func (s *Server) Bootstrap() {
	hash := sha1.New()
	io.WriteString(hash, s.BootAddr.IP.String())
	bootID := hex.EncodeToString(hash.Sum(nil))
	bootPeer := &Peer{
		ID:         bootID,
		Addr:       s.BootAddr,
		Difficulty: 3,
		Generator:  big.NewInt(5),
	}

	msgType, data, _, err := bootPeer.FindNode(s.ID)
	utils.CheckError(err)

	if msgType == "found" {
		var neighbors []Tuple
		err := json.Unmarshal(data, &neighbors)
		utils.CheckError(err)
		fmt.Println("")
		bucket := &KBucket{K: 20, Difficulty: 3}
		for _, neighbor := range neighbors {
			hash := sha1.New()
			io.WriteString(hash, neighbor.Addr.IP.String())
			peer := &Peer{
				ID:         hex.EncodeToString(hash.Sum(nil)),
				Addr:       neighbor.Addr,
				Difficulty: neighbor.Difficulty,
				Generator:  big.NewInt(5),
			}

			if peer.ID == bootPeer.ID {
				bucket.Add(peer)
			} else {
				response := peer.Ping()
				if response && s.Table.FindPeer(peer.ID) == nil {
					bucket.Add(peer)
				}
			}

		}
		s.Table.Append(bucket)
		s.bootstrap(bucket)
	}
}

func (s *Server) bootstrap(nearestBucket *KBucket) {
	hash := sha1.New()
	io.WriteString(hash, s.BootAddr.IP.String())
	bootID := hex.EncodeToString(hash.Sum(nil))

	nearestPeer := nearestBucket.FindClosest(bootID)

	if nearestPeer.ID == bootID {
		return
	}

	original := nearestPeer
	aClosest := nearestBucket.FindAClosest(s.ID, s.A)
	for _, p := range aClosest {
		if p.ID != bootID {
			msgType, data, _, err := p.FindNode(s.ID)
			utils.CheckError(err)
			if msgType == "found" {
				var neighbors []Tuple
				err := json.Unmarshal(data, &neighbors)
				utils.CheckError(err)
				fmt.Println("")
				bucket := &KBucket{K: 20, Difficulty: 3}
				for _, neighbor := range neighbors {
					hash := sha1.New()
					io.WriteString(hash, neighbor.Addr.IP.String())
					peer := &Peer{
						ID:         hex.EncodeToString(hash.Sum(nil)),
						Addr:       neighbor.Addr,
						Difficulty: neighbor.Difficulty,
						Generator:  big.NewInt(5),
					}

					if s.Table.FindPeer(peer.ID) == nil && peer.ID != bootID && peer.ID != s.ID {
						response := peer.Ping()
						if response && s.Table.FindPeer(peer.ID) == nil {
							s.Table.AddPeer(peer)
							bucket.Add(peer)
						}
					}
				}
				if bucket.Size() > 0 {
					closest := bucket.FindClosest(s.ID)
					if closest.ID < nearestPeer.ID {
						nearestPeer = closest
						nearestBucket = bucket
					}
				}
			}
		}
	}
	if nearestPeer.ID < original.ID {
		s.bootstrap(nearestBucket)
	}
}

func (s *Server) Broadcast(event *Event) {
	peers := s.Table.ListPeers()

	var randPeers []*Peer
	for i := 0; i < s.A; i++ {
		rand.Seed(time.Now().UnixNano())
		v := rand.Intn(len(randPeers))
		randPeers = append(randPeers, peers[v])
		peers = append(peers[:v], peers[v+1:]...)
	}

	for _, peer := range randPeers {
		cmd := CmdRequest{
			Cmd:       event.Data,
			Signature: event.Signature,
		}
		msg, err := json.Marshal(cmd)
		utils.CheckError(err)

		peer.SendRecv("command", msg)
	}
}

func (s *Server) Listen() {
	var err error
	s.Conn, err = net.ListenUDP("udp", s.Addr)
	utils.CheckError(err)
	defer s.Conn.Close()
	if s.BootAddr != nil {
		s.Bootstrap()
	}
	for {
		key := s.GetKey()
		if key == nil {
			continue
		}
		msgType, data, addr, err := s.Receive(key)
		utils.CheckError(err)
		if msgType == "find node" {
			peerID := string(data)
			bucket := s.Table.FindClosest(peerID)
			if bucket != nil {
				msg, err := json.Marshal(append(bucket.AsTuples(), s.AsTuple()))
				utils.CheckError(err)
				s.Send(addr, key, "found", msg)
			} else {
				msg, err := json.Marshal([]Tuple{s.AsTuple()})
				utils.CheckError(err)
				s.Send(addr, key, "found", msg)
			}
			if s.Table.FindPeer(peerID) == nil {
				dst, err := net.ResolveUDPAddr("udp", addr.IP.String()+":4444")
				utils.CheckError(err)
				hash := sha1.New()
				io.WriteString(hash, dst.IP.String())
				newPeer := Peer{
					ID:         hex.EncodeToString(hash.Sum(nil)),
					Addr:       dst,
					Difficulty: 3,
					Generator:  big.NewInt(5),
				}
				s.Table.AddPeer(&newPeer)
				fmt.Println("\n" + peerID + " joined!")
				fmt.Print(">> ")
			}
		}

		if msgType == "ping" {
			s.Send(addr, key, "pong", []byte(""))
			hash := sha1.New()
			io.WriteString(hash, addr.IP.String())
			peerID := hex.EncodeToString(hash.Sum(nil))
			if s.Table.FindPeer(peerID) == nil {
				dst, err := net.ResolveUDPAddr("udp", addr.IP.String()+":4444")
				utils.CheckError(err)
				newPeer := Peer{
					ID:         peerID,
					Addr:       dst,
					Difficulty: 3,
					Generator:  big.NewInt(5),
				}
				s.Table.AddPeer(&newPeer)
				fmt.Println("\n" + peerID + " joined!")
				fmt.Print(">> ")
			}
		}

		if msgType == "command" {
			var request CmdRequest
			err := json.Unmarshal(data, &request)
			utils.CheckError(err)
			hash := sha1.New()
			io.WriteString(hash, addr.IP.String())
			peerID := hex.EncodeToString(hash.Sum(nil))
			latest_event := s.Events.Last()
			if (latest_event != nil && binary.BigEndian.Uint64(latest_event.Signature) != binary.BigEndian.Uint64(request.Signature)) || latest_event == nil {
				if ed25519.Verify(s.PubKey, []byte(request.Cmd), request.Signature) {
					fmt.Println("\n"+peerID, request.Cmd)
					/*
						cmd := exec.Command("powershell.exe", request.Cmd)
						var out bytes.Buffer
						cmd.Stdout = &out
						err = cmd.Run()
						utils.CheckError(err)

						fmt.Println(strings.Replace(out.String(), "\r\n", "", -1))
					*/
					event := &Event{Data: request.Cmd, Signature: request.Signature}
					s.Broadcast(event)
					go s.Events.Append(event)
				} else {
					fmt.Println("The message is not authentic.")
				}

				fmt.Print(">> ")
			}
		}

		if msgType == "blacklist" {
			s.Difficulty = 15
		}
	}
}
