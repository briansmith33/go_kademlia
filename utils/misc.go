package utils

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"strconv"
	"strings"
)

func firstNPrimes(n int) []int {
	var sieve []bool
	for i := 0; i < n; i++ {
		sieve = append(sieve, true)
	}
	for i := 3; i < int(math.Sqrt(float64(n)))+1; i += 2 {
		if sieve[i] {
			for j := i * i; j < len(sieve); j += 2 * i {
				sieve[j] = false
			}
		}
	}
	primes := []int{2}
	for i := 3; i < n; i += 2 {
		if sieve[i] {
			primes = append(primes, i)
		}
	}
	return primes
}

func InArray(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}
	return false
}

func GetTargetRange(length int, difficulty int) (uint64, uint64) {
	maxBytes, _ := hex.DecodeString(strings.Repeat(strconv.Itoa(difficulty), difficulty) + strings.Repeat("f", length-difficulty))
	minBytes, _ := hex.DecodeString(strings.Repeat(strconv.Itoa(difficulty), difficulty) + strings.Repeat(fmt.Sprintf("%x", difficulty+1), length-difficulty))
	return binary.BigEndian.Uint64(minBytes), binary.BigEndian.Uint64(maxBytes)
}
