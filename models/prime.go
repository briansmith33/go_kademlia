package models

import "math"

type Prime struct {
	NBits int
	Seed  int
}

func (p *Prime) GetLowLevelPrime() {
	//firstPrimes := p.FirstNPrimes(1000)

}

func (p *Prime) FirstNPrimes(n int) []int {
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
