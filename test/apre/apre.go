package apre

import (
	"crypto/rand"
	"math/big"

	// bn128 "github.com/fentec-project/bn256"
	bn128 "pvpre/bn128"
)

type Param struct {
	G1 *bn128.G1
	G2 *bn128.G1
	H1 *bn128.G2
	H2 *bn128.G1
	L  *bn128.GT
}

type SK struct {
	Xx *big.Int
	Yx *big.Int
}

type PK struct {
	X *bn128.G2
	Y *bn128.G1
}

type C struct {
	C0 *bn128.GT
	C1 *bn128.G1
	C2 *bn128.GT
	C3 *bn128.G2
}

type Cp struct {
	C0p *bn128.GT
	C1p *bn128.G1
	C2p *bn128.GT
}

func Setup() *Param {
	seed1, _ := rand.Int(rand.Reader, bn128.Order)
	g1 := new(bn128.G1).ScalarBaseMult(seed1)
	seed2, _ := rand.Int(rand.Reader, bn128.Order)
	g2 := new(bn128.G1).ScalarBaseMult(seed2)
	seed3, _ := rand.Int(rand.Reader, bn128.Order)
	h1 := new(bn128.G2).ScalarBaseMult(seed3)
	seed4, _ := rand.Int(rand.Reader, bn128.Order)
	h2 := new(bn128.G1).ScalarBaseMult(seed4)
	L := bn128.Pair(h2, h1)

	param := &Param{
		G1: g1,
		G2: g2,
		H1: h1,
		H2: h2,
		L:  L,
	}
	return param
}

func Encrypt(param *Param, pki *PK, m *bn128.GT) *C {
	r, _ := rand.Int(rand.Reader, bn128.Order)
	Lr := param.L.ScalarMult(param.L, r)
	c0 := new(bn128.GT).Add(Lr, m)
	c1 := param.G1.ScalarMult(param.G1, r)
	eh1g2 := bn128.Pair(param.G2, param.H1)
	c2 := eh1g2.ScalarMult(eh1g2, r)
	c3 := new(bn128.G2).ScalarMult(pki.X, r)

	c := &C{
		C0: c0,
		C1: c1,
		C2: c2,
		C3: c3,
	}
	return c
}

func ReKeyGen(param *Param, ski *SK, pkj *PK, pkp *bn128.G1) *bn128.G1 {
	exp := new(big.Int).ModInverse(ski.Xx, bn128.Order)
	temp := new(bn128.G1).Add(param.H2, pkj.Y)
	temp.Add(temp, pkp)
	w := new(bn128.G1).ScalarMult(temp, exp)
	return w
}

func ReEnc(param *Param, rk *bn128.G1, skp *big.Int, c *C) *Cp {
	c0p := c.C0
	c1p := c.C1
	ec3w := bn128.Pair(rk, c.C3)
	c2z := new(bn128.GT).ScalarMult(c.C2, skp)
	c2zn := new(bn128.GT).Neg(c2z)
	c2p := new(bn128.GT).Add(ec3w, c2zn)
	cp := &Cp{
		C0p: c0p,
		C1p: c1p,
		C2p: c2p,
	}
	return cp
}

func Dec1(param *Param, skj *SK, cp *Cp) *bn128.GT {
	c2pn := new(bn128.GT).Neg(cp.C2p)
	eh1c1p := bn128.Pair(cp.C1p, param.H1)
	eh1c1pyj := new(bn128.GT).ScalarMult(eh1c1p, skj.Yx)
	temp := new(bn128.GT).Add(cp.C0p, eh1c1pyj)
	m := new(bn128.GT).Add(temp, c2pn)
	return m
}
