package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"kademlia/models"
	"kademlia/utils"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
)

func GetOutboundIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP
}

func main() {

	args := os.Args[1:]
	var server models.Server
	var err error

	addr, err := net.ResolveUDPAddr("udp", GetOutboundIP().String()+":4444")
	utils.CheckError(err)
	server.Addr = addr

	if len(args) >= 1 {
		addr, err := net.ResolveUDPAddr("udp", args[0]+":4444")
		utils.CheckError(err)
		server.BootAddr = addr
	}

	server.Table = models.RoutingTable{K: 20}
	server.Events = models.EventChain{Difficulty: 3}
	hash := sha1.New()
	io.WriteString(hash, server.Addr.IP.String())
	server.ID = hex.EncodeToString(hash.Sum(nil))
	server.Generator = big.NewInt(5)
	server.Difficulty = 3
	server.A = 3
	server.PubKey = []byte{4, 30, 248, 199, 208, 99, 69, 5, 31, 162, 148, 19, 16, 254, 113, 194, 35, 64, 152, 18, 156, 84, 48, 56, 57, 59, 50, 81, 117, 79, 62, 57}

	var privKey ed25519.PrivateKey
	privKey, err = ioutil.ReadFile("priv_key.pem")
	if err != nil {
		log.Fatalf("error while reading %v", err)
	}

	go server.Listen()
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print(">> ")
		text, _ := reader.ReadString('\n')
		text = strings.Replace(text, "\r\n", "", -1)
		signature := ed25519.Sign(privKey, []byte(text))
		event := &models.Event{Data: text, Signature: signature}
		server.Events.Append(event)
		server.Broadcast(event)
	}
}
