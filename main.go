package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"
)

type JWT struct {
	b64Header     string
	b64Payload    string
	b64Signature  string
	signedContent string
	signature     []byte
}

func JWTFromString(s string) (*JWT, error) {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("We have %d parts, expected 3", len(parts))
	}

	signedContent := strings.Join(parts[:2], ".")

	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}

	return &JWT{
		b64Header:     parts[0],
		b64Payload:    parts[1],
		b64Signature:  parts[2],
		signedContent: signedContent,
		signature:     signature,
	}, nil
}

func (jwt *JWT) isSignedWithKey(key []byte) bool {
	mac := hmac.New(sha256.New, key)
	if _, err := mac.Write([]byte(jwt.signedContent)); err != nil {
		panic(err)
	}
	expectedMac := mac.Sum(nil)
	return hmac.Equal(expectedMac, jwt.signature)
}

func doGenerate(alphabet string, base []byte, length int, dest chan []byte) {
	if len(base) == length {
		key := make([]byte, length)
		copy(key, base)
		dest <- key
		return
	}

	for index := range alphabet {
		key := append(base, alphabet[index])
		doGenerate(alphabet, key, length, dest)
	}
}

func generate(alphabet string, maxLength int, dest chan []byte) {
	for length := 1; length <= maxLength; length++ {
		doGenerate(alphabet, make([]byte, 0, length), length, dest)
	}
}

func main() {
	alphabet := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	maxLength := 6

	result := make(chan string)
	defer close(result)
	keys := make(chan []byte)

	jwt, jwtErr := JWTFromString("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.cAOIAifu3fykvhkHpbuhbvtH807-Z2rI1FS3vX1XMjE")
	if jwtErr != nil {
		panic(jwtErr)
	}

	go generate(alphabet, maxLength, keys)

	var wg sync.WaitGroup

	done := make(chan struct{}, runtime.NumCPU()*2)

	previousNumberOfTestedKeys := 0
	numberOfTestedKeys := 0
	lock := sync.Mutex{}

	delay := 5 * time.Second
	ticker := time.Tick(delay)
	go func() {
		for range ticker {
			func() {
				lock.Lock()
				defer lock.Unlock()
				fmt.Printf("\r%d keys tested (%.1f/s)", numberOfTestedKeys, float64(numberOfTestedKeys-previousNumberOfTestedKeys)/5.0)
				previousNumberOfTestedKeys = numberOfTestedKeys
			}()
		}
	}()
MAINLOOP:
	for {
		select {
		case key := <-result:
			fmt.Printf("\nKey is \"%s\" (tested %d keys)\n", key, numberOfTestedKeys)
			close(keys)
			close(done)
			break MAINLOOP
		case key := <-keys:
			done <- struct{}{}
			wg.Add(1)
			go func(key []byte) {
				defer wg.Done()
				if jwt.isSignedWithKey(key) {
					result <- string(key)
				}
				go func() {
					lock.Lock()
					defer lock.Unlock()
					numberOfTestedKeys++
				}()
				<-done
			}(key)
		}
	}
	wg.Wait()
}
