/*
Copyright (c) 2011, G. Ryan Sablosky
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.
Redistributions in binary form must reproduce the above copyright notice, this
list of conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

package main

import (
"fmt"
"os"
"os/exec"
"net"
"strings"
"bytes"
"flag"

"crypto/aes"
"crypto/cipher"
"crypto/md5"

"github.com/kless/goconfig/config"
)

type packetV2 struct {
	deviceId  string
	noteId    string
	eventType string
	data       string
	contents   string
}

var trustId string
var configLocation string

func init() {
	flag.StringVar(&trustId, "t", "", "Trust the provided device ID.")
	flag.StringVar(&configLocation, "c", "", "Set config file location")
	flag.Parse()
}

//Creates an MD5 digest from a byte string.
func doDigest(in []byte) []byte {
	hash := md5.New()
	hash.Write(in)
	return hash.Sum()
}

//Generates the key from the passphrase by hashing it 10 times.
//For some reason. I dunno, I just do what the source code says.
func passphraseToKey(passphrase string) []byte {
	passphraseBytes := []uint8(passphrase)
	for i := 0; i < 10; i++ {
		passphraseBytes = doDigest(passphraseBytes)
	}
	return passphraseBytes
}

//Decrypt a message.
func decryptMessage(key []byte, ciphertext *bytes.Buffer) (buf *bytes.Buffer) {
	iv := doDigest(key)
	aescrypt, _ := aes.NewCipher(key)
	cipher := cipher.NewCBCDecrypter(aescrypt, iv)
	out := bytes.NewBuffer(make([]byte, 512))
	cipher.CryptBlocks(out.Bytes(), ciphertext.Bytes())
	return out
}


//Sends a notification using exec and the "notify-send" program.
func sendNotify(msg packetV2, icon string) error {
	switch {
	case msg.eventType == "RING":
		icon = icon + "/ring.png"
	case msg.eventType == "SMS":
		icon = icon + "/sms.png"
	case msg.eventType == "MMS":
		icon = icon + "/mms.png"
	case msg.eventType == "BATTERY":
		icon = icon + "/battery_unknown.png"
	case msg.eventType == "PING":
		icon = icon + "/app-icon.png"
	}

	cmd := exec.Command("notify-send",
	"-i", icon, msg.eventType, msg.contents)

	cmdErr := cmd.Run()
	return cmdErr
}

func elem(input string, list []string) bool {
	for _, v := range list {
		if input == v {
			return true
		}
	}
	return false
}

//Splits a notify-packet into its fields.
func splitPacket(input string) packetV2 {
	pkt := make([]string, 6)
	if strings.HasPrefix(input, "v2") {
		pkt = strings.SplitN(input, "/", 6)
	} else {
		fmt.Println("Unsupported packet type")
		os.Exit(2)
	}
	return packetV2{pkt[1], pkt[2], pkt[3], pkt[4], pkt[5]}
}

func loadConfig() *config.Config {
	configDirs := strings.Split(os.Getenv("XDG_CONFIG_HOME") + ":"	+ os.Getenv("XDG_CONFIG_DIRS"), ":")
	for _, d := range configDirs {
		cfg, _ := config.ReadDefault(d + "/android-notify-lite/config")
		if cfg != nil {
			configLocation = d + "/android-notify-lite/config"
			return cfg
		}
	}
	cfg, _ := config.ReadDefault(os.Getenv("HOME")+"/.android-notify-lite")
	configLocation = os.Getenv("HOME") + "/.android-notify-lite"
	if cfg == nil {
		fmt.Println("Error: No configuration file found.")
		os.Exit(1)
	}
	return cfg
}

func main() {
	//Load configuration info
	c := loadConfig()

	iconDir, _ := c.String("Notify", "icon_dir")
	decrypt, _ := c.Bool("Notify", "decrypt")
	passphrase, _ := c.String("Notify", "passphrase")
	broadcastAddr, _ := c.String("Notify", "broadcast_addr")
	rawTrustedIds, _ := c.String("Notify", "trusted_ids")
	trustedIds := strings.Split(rawTrustedIds, "\n")

	if trustId != "" {
		c.RemoveOption("Notify", "trusted_ids")
		c.AddOption("Notify", "trusted_ids", rawTrustedIds + "\n" + trustId)
		c.WriteFile(configLocation, 0600, "Device ID added")
		fmt.Println("ID added to config file.")
		os.Exit(1)
	}

	//Connect to the broadcast address
	socket, netErr := net.ListenUDP("udp4", &net.UDPAddr{
		IP:   net.ParseIP(broadcastAddr),
		Port: 10600,
	})

	if netErr == nil {
		in := bytes.NewBuffer(make([]byte, 512))
		key := passphraseToKey(passphrase)
		for {
			socket.ReadFromUDP(in.Bytes())
			packet := new(packetV2)
			if decrypt {
				msg := decryptMessage(key, in)
				stripped, _ := msg.ReadString(0)
				*packet = splitPacket(stripped)
			} else {
				*packet = splitPacket(string(in.Bytes()))
			}

			if elem(packet.deviceId, trustedIds) {
				sendNotify(*packet, iconDir)
			} else {
				fmt.Printf("Messaged received w/ unknown device id %s",
				packet.deviceId)
			}
		}
	} else {
		fmt.Println("Error with network connection: ", netErr)
		os.Exit(1)
	}
}
