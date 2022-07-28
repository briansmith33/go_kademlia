package models

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"kademlia/constants"
	"kademlia/utils"
	"math/big"
	"net"
	"strconv"
	"strings"
	"time"
)

type Peer struct {
	ID         string       `json:"id"`
	Addr       *net.UDPAddr `json:"address"`
	Left       *Peer        `json:"left"`
	Right      *Peer        `json:"right"`
	Difficulty int          `json:"difficulty"`
	AesKey     []byte       `json:"aes_key"`
	Generator  *big.Int     `json:"generator"`
	PrivKey    *big.Int     `json:"priv_key"`
	PubKey     *big.Int     `json:"pub_key"`
	Prime      *big.Int     `json:"prime"`
	JoinedAt   time.Time    `json:"joined_at"`
	LastLookup time.Time    `json:"last_looup"`
}

func (p *Peer) generatePrime() {
	if p.Prime == nil {
		v, e := rand.Prime(rand.Reader, 2048)
		utils.CheckError(e)
		p.Prime = v
	}
}

func (p *Peer) generatePrivateKey() {
	priv_key := make([]byte, constants.KEY_LENGTH)
	_, err := rand.Read(priv_key)
	utils.CheckError(err)
	p.PrivKey = new(big.Int).SetBytes(priv_key)
}

func (p *Peer) generatePublicKey() {
	var pub_key big.Int
	pub_key.Exp(p.Generator, p.PrivKey, p.Prime)
	p.PubKey = &pub_key
}

func (p *Peer) getKey(remote_pub_key *big.Int) {
	var shared_secret big.Int
	shared_secret.Exp(remote_pub_key, p.PrivKey, p.Prime)
	hash := sha256.New()
	hash.Write(shared_secret.Bytes())
	p.AesKey = hash.Sum(nil)
}

func (p *Peer) calculateNonce() int {
	minInt, maxInt := utils.GetTargetRange(len(p.ID), p.Difficulty)
	nonce := 0
	for {
		hash := sha1.New()
		io.WriteString(hash, p.ID+strconv.Itoa(nonce))
		h := binary.BigEndian.Uint64(hash.Sum(nil))
		if minInt < h && h < maxInt {
			return nonce
		}
		nonce += 1
	}
}

func (p *Peer) Copy() *Peer {
	return &Peer{Addr: p.Addr, Difficulty: p.Difficulty}
}

func (p *Peer) AsTuple() Tuple {
	return Tuple{Addr: p.Addr, Difficulty: p.Difficulty}
}

func (p *Peer) Blacklist() {
	p.Difficulty = 15
	conn, err := net.DialUDP("udp", nil, p.Addr)
	utils.CheckError(err)
	defer conn.Close()
	p.Send(conn, "blacklist", []byte(""))
}

func (p *Peer) PerformKeyExchange() bool {
	p.generatePrime()
	p.generatePrivateKey()
	p.generatePublicKey()

	offer := KeyOffer{
		Type:  "key exchange",
		Nonce: p.calculateNonce(),
		Prime: p.Prime,
		Key:   p.PubKey,
	}

	data, err := json.Marshal(offer)
	utils.CheckError(err)
	b64 := base64.StdEncoding.EncodeToString(data)
	msg := b64 + "<EOF>"
	conn, err := net.DialUDP("udp", nil, p.Addr)
	utils.CheckError(err)
	defer conn.Close()
	conn.Write([]byte(msg))
	msg = ""
	for {
		chunk := make([]byte, constants.BUFFER)
		_, _, err := conn.ReadFromUDP(chunk)
		if err != nil {
			return false
		}
		msg += strings.TrimSpace(string(chunk))
		if strings.Contains(msg, "<EOF>") {
			break
		}
	}
	msg = strings.Replace(msg, "<EOF>", "", -1)
	byteData, _ := base64.StdEncoding.DecodeString(msg)
	var jsonData KeyOffer
	json.Unmarshal(byteData, &jsonData)
	p.getKey(jsonData.Key)
	return true
}

func (p *Peer) Send(conn *net.UDPConn, msgType string, msgData []byte) bool {
	response := p.PerformKeyExchange()
	if !response {
		return false
	}
	msg := Msg{Type: msgType, Data: msgData}
	marshalledMsg, err := json.Marshal(msg)
	utils.CheckError(err)
	encrypted_data := utils.Encrypt(marshalledMsg, p.AesKey)
	conn.Write([]byte(encrypted_data + "<EOF>"))
	return true
}

func (p *Peer) Receive(conn *net.UDPConn) (string, []byte, *net.UDPAddr, error) {
	var msg string
	var addr net.Addr
	var err error

	for {
		chunk := make([]byte, constants.BUFFER)
		_, addr, err = conn.ReadFromUDP(chunk)

		msg += strings.TrimSpace(string(chunk))
		if strings.Contains(msg, "<EOF>") {
			break
		}
	}
	msg = strings.Replace(msg, "<EOF>", "", -1)
	decrypted := utils.Decrypt(msg, p.AesKey)

	var jsonData Msg
	json.Unmarshal([]byte(decrypted), &jsonData)
	return jsonData.Type, jsonData.Data, addr.(*net.UDPAddr), err
}

func (p *Peer) SendRecv(msgType string, msgData []byte) (string, []byte, *net.UDPAddr, error) {
	conn, err := net.DialUDP("udp", nil, p.Addr)
	utils.CheckError(err)
	defer conn.Close()
	sent := p.Send(conn, msgType, msgData)
	if !sent {
		return "", []byte(""), nil, errors.New("no response")
	}
	return p.Receive(conn)
}

func (p *Peer) Ping() bool {
	msgType, _, _, err := p.SendRecv("ping", []byte(""))
	if err != nil {
		return false
	}
	if msgType == "pong" {
		return true
	}
	return false
}

func (p *Peer) FindNode(id string) (string, []byte, *net.UDPAddr, error) {
	return p.SendRecv("find node", []byte(id))
}

func (p *Peer) Store(key string, value string) {

}

func (p *Peer) FindValue(id string) {

}
