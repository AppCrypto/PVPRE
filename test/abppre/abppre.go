package abppre

import (
	"crypto/rand"
	"crypto/sha256"
	"math/big"

	// bn128 "github.com/fentec-project/bn256"
	bn128 "pvpre/bn128"
)

type H1Func func(*bn128.GT) *big.Int

type H2Func func(*bn128.GT) *big.Int

type Params struct {
	// 群G用bn128.G1
	// 群G1用bn128.G2
	G  *bn128.G1 //G的生成元
	G1 *bn128.G2 //G1中的生成元
	Q  *big.Int
	H1 H1Func
	H2 H2Func
}

type RK struct {
	Rk1 *bn128.G1
	Rk2 *bn128.GT
	Rk3 *bn128.G2
	Ti  *bn128.G2
}

type C struct {
	C1 *bn128.G1
	C2 *bn128.GT
	C3 *bn128.G1
}

type Cp struct {
	C1p *bn128.G1
	C2p *bn128.GT
	C3p *bn128.G1
	C4p *bn128.G1
	C5p *bn128.GT
}

// RandomElementInZqStar generates a random non-zero element in Z_q*
func RandomElementInZqStar() *big.Int {
	q := bn128.Order
	var r *big.Int
	for {
		// Generate a random number in [0, q-1]
		r, _ = rand.Int(rand.Reader, q)
		// Ensure it's non-zero
		if r.Sign() != 0 {
			break
		}
	}
	return r
}

func SerializeGT(elem *bn128.GT) []byte {
	return elem.Marshal()
}

// H1: G2 → Z_q
func H1func(input *bn128.GT) *big.Int {
	q := bn128.Order
	var result *big.Int
	for {
		// Step 1: Serialize the input element
		serialized := SerializeGT(input)
		// Modify the serialized input slightly to avoid hash collisions
		serialized = append(serialized, 0x00)
		// Step 2: Hash the serialized bytes using SHA-256
		hash := sha256.Sum256(serialized)
		// Step 3: Convert the hash to a big.Int and reduce modulo q
		result = new(big.Int).SetBytes(hash[:])
		result.Mod(result, q)

		// Step 4: Ensure result is non-zero
		if result.Sign() != 0 {
			break
		}
	}
	return result
}

// H2: G2 → Z_q
func H2func(input *bn128.GT) *big.Int {
	q := bn128.Order
	var result *big.Int

	for {
		// Step 1: Serialize the input element
		serialized := SerializeGT(input)
		// Modify the serialized input slightly to avoid hash collisions
		serialized = append(serialized, 0xFF)
		// Step 2: Hash the serialized bytes using SHA-256
		hash := sha256.Sum256(serialized)
		// Step 3: Modify the hash slightly for H2 to distinguish it from H1
		hash[len(hash)-1] ^= 0xFF // Slightly modify the hash
		// Step 4: Convert the hash to a big.Int and reduce modulo q
		result = new(big.Int).SetBytes(hash[:])
		result.Mod(result, q)
		// Step 5: Ensure result is non-zero
		if result.Sign() != 0 {
			break
		}

	}
	return result
}

func Setup() *Params {
	g := new(bn128.G1).ScalarBaseMult(big.NewInt(1))
	// seed1, _ := rand.Int(rand.Reader, bn128.Order)
	g1 := new(bn128.G2).ScalarBaseMult(big.NewInt(1))
	H1 := func(input *bn128.GT) *big.Int {
		return H1func(input) // Hfunc 函数用于返回多项式系数
	}
	H2 := func(input *bn128.GT) *big.Int {
		return H2func(input)
	}
	params := &Params{
		G:  g,
		G1: g1,
		Q:  bn128.Order,
		H1: H1,
		H2: H2,
	}
	return params
}

func ReKeyGen(params *Params, ski *big.Int, pkij *bn128.G1, wi *bn128.GT) *RK {
	seed1, _ := rand.Int(rand.Reader, bn128.Order)
	Xij := new(bn128.GT).ScalarBaseMult(seed1)
	rij := RandomElementInZqStar()
	rk1 := new(bn128.G1).ScalarBaseMult(rij)
	pkijrij := new(bn128.G1).ScalarMult(pkij, rij)
	temp := bn128.Pair(pkijrij, params.G1)
	rk2 := new(bn128.GT).Add(Xij, temp)
	h1 := params.H1(Xij)
	exp := new(big.Int).Sub(h1, ski)
	// exp.Mod(exp, params.Q)
	if exp.Sign() < 0 {
		exp.Add(exp, params.Q)
	}
	rk3 := new(bn128.G2).ScalarMult(params.G1, exp)

	// seed2, _ := rand.Int(rand.Reader, bn128.Order)
	// wi := new(bn128.G2).ScalarBaseMult(seed2)
	h2 := params.H2(wi)
	ti := new(bn128.G2).ScalarMult(params.G1, h2)

	rk := &RK{
		Rk1: rk1,
		Rk2: rk2,
		Rk3: rk3,
		Ti:  ti,
	}

	return rk
}

func Encrypt(params *Params, pki *bn128.G1, m *bn128.GT, wi *bn128.GT) *C {
	r := RandomElementInZqStar()
	c1 := new(bn128.G1).ScalarMult(params.G, r)
	h2 := params.H2(wi)
	g1h2 := new(bn128.G2).ScalarMult(params.G1, h2)
	temp := bn128.Pair(pki, g1h2)
	temp2 := new(bn128.GT).ScalarMult(temp, r)
	c2 := new(bn128.GT).Add(m, temp2)
	exp := new(big.Int).Mul(h2, r)
	// exp.Mod(exp, bn128.Order)
	c3 := new(bn128.G1).ScalarMult(params.G, exp)
	c := &C{
		C1: c1,
		C2: c2,
		C3: c3,
	}
	return c
}

func ReEnc(params *Params, pki *bn128.G1, pkij *bn128.G1, rk *RK, c *C) *Cp {
	c1p := c.C1
	temp := bn128.Pair(c.C3, rk.Rk3)
	c2p := new(bn128.GT).Add(c.C2, temp)
	c3p := c.C3
	c4p := rk.Rk1
	c5p := rk.Rk2
	cp := &Cp{
		C1p: c1p,
		C2p: c2p,
		C3p: c3p,
		C4p: c4p,
		C5p: c5p,
	}
	return cp
}

func Dec(params *Params, cp *Cp, skij *big.Int) *bn128.GT {
	g1skij := new(bn128.G2).ScalarMult(params.G1, skij)
	temp := bn128.Pair(cp.C4p, g1skij)
	temp.Neg(temp)
	Xij := new(bn128.GT).Add(cp.C5p, temp)
	g1h1 := new(bn128.G2).ScalarMult(params.G1, params.H1(Xij))
	temp2 := bn128.Pair(cp.C3p, g1h1)
	temp2.Neg(temp2)
	m := new(bn128.GT).Add(cp.C2p, temp2)
	return m
}
