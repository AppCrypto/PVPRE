package bn256

// For details of the algorithms used, see "Multiplication and Squaring on
// Pairing-Friendly Fields, Devegili et al.
// http://eprint.iacr.org/2006/471.pdf.

// gfP2 implements a field of size p² as a quadratic extension of the base field
// where i²=-1.


import (
	"math/big"
)

type gfP2 struct {
	x, y gfP // value is xi+y.
}

func gfP2Decode(in *gfP2) *gfP2 {
	out := &gfP2{}
	montDecode(&out.x, &in.x)
	montDecode(&out.y, &in.y)
	return out
}

func (e *gfP2) String() string {
	return "(" + e.x.String() + ", " + e.y.String() + ")"
}

func (e *gfP2) Set(a *gfP2) *gfP2 {
	e.x.Set(&a.x)
	e.y.Set(&a.y)
	return e
}

func (e *gfP2) SetZero() *gfP2 {
	e.x = gfP{0}
	e.y = gfP{0}
	return e
}

func (e *gfP2) SetOne() *gfP2 {
	e.x = gfP{0}
	e.y = *newGFp(1)
	return e
}

func (e *gfP2) IsZero() bool {
	zero := gfP{0}
	return e.x == zero && e.y == zero
}

func (e *gfP2) IsOne() bool {
	zero, one := gfP{0}, *newGFp(1)
	return e.x == zero && e.y == one
}

func (e *gfP2) Conjugate(a *gfP2) *gfP2 {
	e.y.Set(&a.y)
	gfpNeg(&e.x, &a.x)
	return e
}

func (e *gfP2) Neg(a *gfP2) *gfP2 {
	gfpNeg(&e.x, &a.x)
	gfpNeg(&e.y, &a.y)
	return e
}

func (e *gfP2) Add(a, b *gfP2) *gfP2 {
	gfpAdd(&e.x, &a.x, &b.x)
	gfpAdd(&e.y, &a.y, &b.y)
	return e
}

func (e *gfP2) Sub(a, b *gfP2) *gfP2 {
	gfpSub(&e.x, &a.x, &b.x)
	gfpSub(&e.y, &a.y, &b.y)
	return e
}

// See "Multiplication and Squaring in Pairing-Friendly Fields",
// http://eprint.iacr.org/2006/471.pdf
func (e *gfP2) Mul(a, b *gfP2) *gfP2 {
	tx, t := &gfP{}, &gfP{}
	gfpMul(tx, &a.x, &b.y)
	gfpMul(t, &b.x, &a.y)
	gfpAdd(tx, tx, t)

	ty := &gfP{}
	gfpMul(ty, &a.y, &b.y)
	gfpMul(t, &a.x, &b.x)
	gfpSub(ty, ty, t)

	e.x.Set(tx)
	e.y.Set(ty)
	return e
}

func (e *gfP2) MulScalar(a *gfP2, b *gfP) *gfP2 {
	gfpMul(&e.x, &a.x, b)
	gfpMul(&e.y, &a.y, b)
	return e
}

// MulXi sets e=ξa where ξ=i+9 and then returns e.
func (e *gfP2) MulXi(a *gfP2) *gfP2 {
	// (xi+y)(i+9) = (9x+y)i+(9y-x)
	tx := &gfP{}
	gfpAdd(tx, &a.x, &a.x)
	gfpAdd(tx, tx, tx)
	gfpAdd(tx, tx, tx)
	gfpAdd(tx, tx, &a.x)

	gfpAdd(tx, tx, &a.y)

	ty := &gfP{}
	gfpAdd(ty, &a.y, &a.y)
	gfpAdd(ty, ty, ty)
	gfpAdd(ty, ty, ty)
	gfpAdd(ty, ty, &a.y)

	gfpSub(ty, ty, &a.x)

	e.x.Set(tx)
	e.y.Set(ty)
	return e
}

func (e *gfP2) Square(a *gfP2) *gfP2 {
	// Complex squaring algorithm:
	// (xi+y)² = (x+y)(y-x) + 2*i*x*y
	tx, ty := &gfP{}, &gfP{}
	gfpSub(tx, &a.y, &a.x)
	gfpAdd(ty, &a.x, &a.y)
	gfpMul(ty, tx, ty)

	gfpMul(tx, &a.x, &a.y)
	gfpAdd(tx, tx, tx)

	e.x.Set(tx)
	e.y.Set(ty)
	return e
}

func (e *gfP2) Invert(a *gfP2) *gfP2 {
	// See "Implementing cryptographic pairings", M. Scott, section 3.2.
	// ftp://136.206.11.249/pub/crypto/pairings.pdf
	t1, t2 := &gfP{}, &gfP{}
	gfpMul(t1, &a.x, &a.x)
	gfpMul(t2, &a.y, &a.y)
	gfpAdd(t1, t1, t2)

	inv := &gfP{}
	inv.Invert(t1)

	gfpNeg(t1, &a.x)

	gfpMul(&e.x, t1, inv)
	gfpMul(&e.y, &a.y, inv)
	return e
}



func (e *gfP) divBy2(a *gfP) (*gfP, error) {
	aInt, err := a.ToInt()
	if err != nil {
		return nil, err
	}
	if new(big.Int).Mod(aInt, big.NewInt(2)).Sign() == 0 {
		return e.SetInt(new(big.Int).Div(aInt, big.NewInt(2))), nil
	}
	s := new(big.Int).Add(aInt, P)
	return e.SetInt(new(big.Int).Div(s, big.NewInt(2))), nil
}

// Sqrt returns square root of g. Let's say g = a + b*i and tSqrt = sqrt(a^2 + b^2).
// Then Sqrt(g) = sqrt((a + tSqrt)/2) + i * b * 1 / (2*sqrt((a + tSqrt)/2)).
func (e *gfP2) Sqrt(g *gfP2) (*gfP2, error) {
	yy, xx, t, tSqrt, z, newY, newYInv, xDiv2, newX := &gfP{}, &gfP{}, &gfP{}, &gfP{},
		&gfP{}, &gfP{}, &gfP{}, &gfP{}, &gfP{}
	gfpMul(yy, &g.y, &g.y)
	gfpMul(xx, &g.x, &g.x)
	gfpAdd(t, xx, yy)

	var err error
	tSqrt, err = tSqrt.Sqrt(t)
	if err != nil { // g.Y^2 + g.X^2 is not QR
		return e, err
	}

	gfpAdd(z, tSqrt, &g.y) // Z = g.Y + sqrt(g.Y^2 + g.X^2)
	z, err = z.divBy2(z)   // Z = (g.Y + sqrt(g.Y^2 + g.X^2)) / 2
	if err != nil {
		return e, err
	}

	newY, err = newY.Sqrt(z)
	if err != nil {
		gfpSub(z, &g.y, tSqrt) // Z = g.Y - sqrt(g.Y^2 + g.X^2)
		z, err = z.divBy2(z)   // Z = (g.Y - sqrt(g.Y^2 + g.X^2)) / 2
		if err != nil {
			return e, err
		}
		newY, err = newY.Sqrt(z)
		if err != nil {
			return e, err
		}
	}

	newYInv.Invert(newY)
	xDiv2, err = xDiv2.divBy2(&g.x)
	if err != nil {
		return e, err
	}
	gfpMul(newX, xDiv2, newYInv)

	e.y = *newY
	e.x = *newX

	return e, nil
}
