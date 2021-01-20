package sm2

import (
	"crypto/elliptic"
	"io"
	"math/big"
	"sync"
)
type (
	p256Curve struct {
		*elliptic.CurveParams
	}

	p256Point struct {
		xyz [12]uint64
	}
)

var (
	p256Precomputed *[37][64 * 8]uint64
	precomputeOnce  sync.Once
)


//optMethod includes some optimized methods.
type optMethod interface {
	// CombinedMult implements fast multiplication S1*g + S2*p (g - generator, p - arbitrary point)
	CombinedMult(Precomputed *[37][64 * 8]uint64, baseScalar, scalar []byte) (x, y *big.Int)
	// InitPubKeyTable implements precomputed table of public key
	InitPubKeyTable(x, y *big.Int) (Precomputed *[37][64 * 8]uint64)
	// PreScalarMult implements fast multiplication of public key
	PreScalarMult(Precomputed *[37][64 * 8]uint64, scalar []byte) (x, y *big.Int)
}


func WA_GenerateKey(rand io.Reader) (*PrivateKey, error) {
	c := P256Sm2()

	k, err := randFieldElement(c, rand)
	if err != nil {
		return nil, err
	}
	priv := new(PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = k
	//(1+d)^-1
	priv.DInv = new(big.Int).Add(k, one)
	priv.DInv.ModInverse(priv.DInv, c.Params().N)
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	if opt, ok := c.(optMethod); ok {
		priv.PreComputed = opt.InitPubKeyTable(priv.PublicKey.X, priv.PublicKey.Y)
	}
	return priv, nil
}
func maybeReduceModP(in *big.Int) *big.Int {
	if in.Cmp(sm2P256.P) < 0 {
		return in
	}
	return new(big.Int).Mod(in, sm2P256.P)
}
// fromBig converts a *big.Int into a format used by this code.
func fromBig(out []uint64, big *big.Int) {
	for i := range out {
		out[i] = 0
	}

	for i, v := range big.Bits() {
		out[i] = uint64(v)
	}
}


// Functions implemented in sm2p256_amd64.s
// Montgomery multiplication modulo P256
func sm2p256Mul(res, in1, in2 []uint64)
func p256TestMul(res, in1, in2 []uint64)

// Montgomery square modulo P256
func sm2p256Sqr(res, in []uint64)

// Montgomery multiplication by 1
func sm2p256FromMont(res, in []uint64)

// iff cond == 1  val <- -val
func sm2p256NegCond(val []uint64, cond int)

// if cond == 0 res <- b; else res <- a
func sm2p256MovCond(res, a, b []uint64, cond int)

// Endianness swap
func sm2p256BigToLittle(res []uint64, in []byte)
func sm2p256LittleToBig(res []byte, in []uint64)

// Constant time table access
func sm2p256Select(point, table []uint64, idx int)
func sm2p256SelectBase(point, table []uint64, idx int)

// Montgomery multiplication modulo Ord(G)
func sm2p256OrdMul(res, in1, in2 []uint64)

// Montgomery square modulo Ord(G), repeated n times
func sm2p256OrdSqr(res, in []uint64, n int)

// Point add with in2 being affine point
// If sign == 1 -> in2 = -in2
// If sel == 0 -> res = in1
// if zero == 0 -> res = in2
func sm2p256PointAddAffineAsm(res, in1, in2 []uint64, sign, sel, zero int)

// Point add
func sm2p256PointAddAsm(res, in1, in2 []uint64) int

// Point double
func sm2p256PointDoubleAsm(res, in []uint64)

func p256Inverse(out, in []uint64) {

	var stack [10 * 4]uint64
	p2 := stack[4*0 : 4*0+4]
	p4 := stack[4*1 : 4*1+4]
	p8 := stack[4*2 : 4*2+4]
	p16 := stack[4*3 : 4*3+4]
	p32 := stack[4*4 : 4*4+4]

	p3 := stack[4*5 : 4*5+4]
	p7 := stack[4*6 : 4*6+4]
	p15 := stack[4*7 : 4*7+4]
	p31 := stack[4*8 : 4*8+4]

	sm2p256Sqr(out, in) //2^1

	sm2p256Mul(p2, out, in) // 2^2-2^0
	sm2p256Sqr(out, p2)
	sm2p256Mul(p3, out, in)
	sm2p256Sqr(out, out)
	sm2p256Mul(p4, out, p2) // f*p 2^4-2^0

	sm2p256Sqr(out, p4)
	sm2p256Sqr(out, out)
	sm2p256Sqr(out, out)
	sm2p256Mul(p7, out, p3)
	sm2p256Sqr(out, out)
	sm2p256Mul(p8, out, p4) // ff*p 2^8-2^0

	sm2p256Sqr(out, p8)

	for i := 0; i < 6; i++ {
		sm2p256Sqr(out, out)
	}
	sm2p256Mul(p15, out, p7)
	sm2p256Sqr(out, out)
	sm2p256Mul(p16, out, p8) // ffff*p 2^16-2^0

	sm2p256Sqr(out, p16)
	for i := 0; i < 14; i++ {
		sm2p256Sqr(out, out)
	}
	sm2p256Mul(p31, out, p15)
	sm2p256Sqr(out, out)
	sm2p256Mul(p32, out, p16) // ffffffff*p 2^32-2^0

	//(2^31-1)*2^33+2^32-1
	sm2p256Sqr(out, p31)
	for i := 0; i < 32; i++ {
		sm2p256Sqr(out, out)
	}
	sm2p256Mul(out, out, p32)

	//x*2^32+p32
	for i := 0; i < 32; i++ {
		sm2p256Sqr(out, out)
	}
	sm2p256Mul(out, out, p32)
	//x*2^32+p32
	for i := 0; i < 32; i++ {
		sm2p256Sqr(out, out)
	}
	sm2p256Mul(out, out, p32)
	//x*2^32+p32
	for i := 0; i < 32; i++ {
		sm2p256Sqr(out, out)
	}
	sm2p256Mul(out, out, p32)
	//x*2^32
	for i := 0; i < 32; i++ {
		sm2p256Sqr(out, out)
	}

	//x*2^32+p32
	for i := 0; i < 32; i++ {
		sm2p256Sqr(out, out)
	}
	sm2p256Mul(out, out, p32)

	//x*2^16+p16
	for i := 0; i < 16; i++ {
		sm2p256Sqr(out, out)
	}
	sm2p256Mul(out, out, p16)

	//x*2^8+p8
	for i := 0; i < 8; i++ {
		sm2p256Sqr(out, out)
	}
	sm2p256Mul(out, out, p8)

	//x*2^4+p4
	for i := 0; i < 4; i++ {
		sm2p256Sqr(out, out)
	}
	sm2p256Mul(out, out, p4)

	//x*2^2+p2
	for i := 0; i < 2; i++ {
		sm2p256Sqr(out, out)
	}
	sm2p256Mul(out, out, p2)

	sm2p256Sqr(out, out)
	sm2p256Sqr(out, out)
	sm2p256Mul(out, out, in)
}

// sm2p256Mul operates in a Montgomery domain with R = 2^256 mod p, where p is the
// underlying field of the curve. (See initP256 for the value.) Thus rr here is
// R×R mod p. See comment in Inverse about how this is used.
var rr = []uint64{0x0000000200000003, 0x00000002FFFFFFFF, 0x0000000100000001, 0x0000000400000002}

// p256GetScalar endian-swaps the big-endian scalar value from in and writes it
// to out. If the scalar is equal or greater than the order of the group, it's
// reduced modulo that order.
func p256GetScalar(out []uint64, in []byte) {
	n := new(big.Int).SetBytes(in)

	if n.Cmp(sm2P256.N) >= 0 {
		n.Mod(n, sm2P256.N)
	}
	fromBig(out, n)
}
func scalarIsZero(scalar []uint64) int {
	return uint64IsZero(scalar[0] | scalar[1] | scalar[2] | scalar[3])
}
func uint64IsZero(x uint64) int {
	x = ^x
	x &= x >> 32
	x &= x >> 16
	x &= x >> 8
	x &= x >> 4
	x &= x >> 2
	x &= x >> 1
	return int(x & 1)
}
func initTable() {
	p256Precomputed = new([37][64 * 8]uint64)

	/*	basePoint := []uint64{
		0x79e730d418a9143c, 0x75ba95fc5fedb601, 0x79fb732b77622510, 0x18905f76a53755c6,
		0xddf25357ce95560a, 0x8b4ab8e4ba19e45c, 0xd2e88688dd21f325, 0x8571ff1825885d85,
		0x0000000000000001, 0xffffffff00000000, 0xffffffffffffffff, 0x00000000fffffffe,
	}*/
	basePoint := []uint64{
		0x61328990F418029E, 0x3E7981EDDCA6C050, 0xD6A1ED99AC24C3C3, 0x91167A5EE1C13B05,
		0xC1354E593C2D0DDD, 0xC1F5E5788D3295FA, 0x8D4CFB066E2A48F8, 0x63CD65D481D735BD,
		0x0000000000000001, 0x00000000FFFFFFFF, 0x0000000000000000, 0x0000000100000000,
	}
	t1 := make([]uint64, 12)
	t2 := make([]uint64, 12)
	copy(t2, basePoint)

	zInv := make([]uint64, 4)
	zInvSq := make([]uint64, 4)
	for j := 0; j < 64; j++ {
		copy(t1, t2)
		for i := 0; i < 37; i++ {
			// The window size is 7 so we need to double 7 times.
			if i != 0 {
				for k := 0; k < 7; k++ {
					sm2p256PointDoubleAsm(t1, t1)
				}
			}
			// Convert the point to affine form. (Its values are
			// still in Montgomery form however.)
			p256Inverse(zInv, t1[8:12])
			sm2p256Sqr(zInvSq, zInv)
			sm2p256Mul(zInv, zInv, zInvSq)

			sm2p256Mul(t1[:4], t1[:4], zInvSq)
			sm2p256Mul(t1[4:8], t1[4:8], zInv)

			copy(t1[8:12], basePoint[8:12])
			// Update the table entry
			copy(p256Precomputed[i][j*8:], t1[:8])
		}
		if j == 0 {
			sm2p256PointDoubleAsm(t2, basePoint)
		} else {
			sm2p256PointAddAsm(t2, t2, basePoint)
		}
	}
}
func (p *p256Point) p256BaseMult(scalar []uint64) {
	precomputeOnce.Do(initTable)

	wvalue := (scalar[0] << 1) & 0xff
	sel, sign := boothW7(uint(wvalue))
	sm2p256SelectBase(p.xyz[0:8], p256Precomputed[0][0:], sel)
	sm2p256NegCond(p.xyz[4:8], sign)

	// (This is one, in the Montgomery domain.)
	//p.xyz[8] = 0x0000000000000001
	//p.xyz[9] = 0xffffffff00000000
	//p.xyz[10] = 0xffffffffffffffff
	//p.xyz[11] = 0x00000000fffffffe
	p.xyz[8] = 0x0000000000000001
	p.xyz[9] = 0x00000000FFFFFFFF
	p.xyz[10] = 0x0000000000000000
	p.xyz[11] = 0x0000000100000000
	var t0 p256Point
	// (This is one, in the Montgomery domain.)
	//t0.xyz[8] = 0x0000000000000001
	//t0.xyz[9] = 0xffffffff00000000
	//t0.xyz[10] = 0xffffffffffffffff
	//t0.xyz[11] = 0x00000000fffffffe
	t0.xyz[8] = 0x0000000000000001
	t0.xyz[9] = 0x00000000FFFFFFFF
	t0.xyz[10] = 0x0000000000000000
	t0.xyz[11] = 0x0000000100000000
	index := uint(6)
	zero := sel

	for i := 1; i < 37; i++ {
		if index < 192 {
			wvalue = ((scalar[index/64] >> (index % 64)) + (scalar[index/64+1] << (64 - (index % 64)))) & 0xff
		} else {
			wvalue = (scalar[index/64] >> (index % 64)) & 0xff
		}
		index += 7
		sel, sign = boothW7(uint(wvalue))
		sm2p256SelectBase(t0.xyz[0:8], p256Precomputed[i][0:], sel)
		sm2p256PointAddAffineAsm(p.xyz[0:12], p.xyz[0:12], t0.xyz[0:8], sign, sel, zero)
		zero |= sel
	}
}
func boothW7(in uint) (int, int) {
	var s uint = ^((in >> 7) - 1)
	var d uint = (1 << 8) - in - 1
	d = (d & s) | (in & (^s))
	d = (d >> 1) + (d & 1)
	return int(d), int(s & 1)
}
//fast sm2p256Mult with public key table
func (p *p256Point) p256PreMult(Precomputed *[37][64*8]uint64, scalar []uint64) {
	wvalue := (scalar[0] << 1) & 0xff
	sel, sign := boothW7(uint(wvalue))
	sm2p256SelectBase(p.xyz[0:8], Precomputed[0][0:], sel)
	sm2p256NegCond(p.xyz[4:8], sign)

	// (This is one, in the Montgomery domain.)
	//p.xyz[8] = 0x0000000000000001
	//p.xyz[9] = 0xffffffff00000000
	//p.xyz[10] = 0xffffffffffffffff
	//p.xyz[11] = 0x00000000fffffffe
	p.xyz[8] = 0x0000000000000001
	p.xyz[9] = 0x00000000FFFFFFFF
	p.xyz[10] = 0x0000000000000000
	p.xyz[11] = 0x0000000100000000
	var t0 p256Point
	// (This is one, in the Montgomery domain.)
	//t0.xyz[8] = 0x0000000000000001
	//t0.xyz[9] = 0xffffffff00000000
	//t0.xyz[10] = 0xffffffffffffffff
	//t0.xyz[11] = 0x00000000fffffffe
	t0.xyz[8] = 0x0000000000000001
	t0.xyz[9] = 0x00000000FFFFFFFF
	t0.xyz[10] = 0x0000000000000000
	t0.xyz[11] = 0x0000000100000000
	index := uint(6)
	zero := sel

	for i := 1; i < 37; i++ {
		if index < 192 {
			wvalue = ((scalar[index/64] >> (index % 64)) + (scalar[index/64+1] << (64 - (index % 64)))) & 0xff
		} else {
			wvalue = (scalar[index/64] >> (index % 64)) & 0xff
		}
		index += 7
		sel, sign = boothW7(uint(wvalue))
		sm2p256SelectBase(t0.xyz[0:8], Precomputed[i][0:], sel)
		sm2p256PointAddAffineAsm(p.xyz[0:12], p.xyz[0:12], t0.xyz[0:8], sign, sel, zero)
		zero |= sel
	}
}
func (p *p256Point) CopyConditional(src *p256Point, v int) {
	pMask := uint64(v) - 1
	srcMask := ^pMask

	for i, n := range p.xyz {
		p.xyz[i] = (n & pMask) | (src.xyz[i] & srcMask)
	}
}
func (curve p256Curve) CombinedMult(Precomputed *[37][64*8]uint64, baseScalar, scalar []byte) (x, y *big.Int) {
	scalarReversed := make([]uint64, 4)
	var r1 p256Point
	r2 := new(p256Point)
	p256GetScalar(scalarReversed, baseScalar)
	r1IsInfinity := scalarIsZero(scalarReversed)
	r1.p256BaseMult(scalarReversed)

	p256GetScalar(scalarReversed, scalar)
	r2IsInfinity := scalarIsZero(scalarReversed)
	//fromBig(r2.xyz[0:4], maybeReduceModP(bigX))
	//fromBig(r2.xyz[4:8], maybeReduceModP(bigY))
	//sm2p256Mul(r2.xyz[0:4], r2.xyz[0:4], rr[:])
	//sm2p256Mul(r2.xyz[4:8], r2.xyz[4:8], rr[:])
	//
	//// This sets r2's Z value to 1, in the Montgomery domain.
	////	r2.xyz[8] = 0x0000000000000001
	////	r2.xyz[9] = 0xffffffff00000000
	////	r2.xyz[10] = 0xffffffffffffffff
	////	r2.xyz[11] = 0x00000000fffffffe
	//r2.xyz[8] = 0x0000000000000001
	//r2.xyz[9] = 0x00000000FFFFFFFF
	//r2.xyz[10] = 0x0000000000000000
	//r2.xyz[11] = 0x0000000100000000
	//
	////r2.p256ScalarMult(scalarReversed)
	////sm2p256PointAddAsm(r1.xyz[:], r1.xyz[:], r2.xyz[:])

	//r2.p256ScalarMult(scalarReversed)
	r2.p256PreMult(Precomputed,scalarReversed)

	var sum, double p256Point
	pointsEqual := sm2p256PointAddAsm(sum.xyz[:], r1.xyz[:], r2.xyz[:])
	sm2p256PointDoubleAsm(double.xyz[:], r1.xyz[:])
	sum.CopyConditional(&double, pointsEqual)
	sum.CopyConditional(&r1, r2IsInfinity)
	sum.CopyConditional(r2, r1IsInfinity)
	return sum.p256PointToAffine()
}
func (p *p256Point) p256PointToAffine() (x, y *big.Int) {
	zInv := make([]uint64, 4)
	zInvSq := make([]uint64, 4)
	p256Inverse(zInv, p.xyz[8:12])
	sm2p256Sqr(zInvSq, zInv)
	sm2p256Mul(zInv, zInv, zInvSq)

	sm2p256Mul(zInvSq, p.xyz[0:4], zInvSq)
	sm2p256Mul(zInv, p.xyz[4:8], zInv)

	sm2p256FromMont(zInvSq, zInvSq)
	sm2p256FromMont(zInv, zInv)

	xOut := make([]byte, 32)
	yOut := make([]byte, 32)
	sm2p256LittleToBig(xOut, zInvSq)
	sm2p256LittleToBig(yOut, zInv)

	return new(big.Int).SetBytes(xOut), new(big.Int).SetBytes(yOut)
}

//precompute public key table
func (curve p256Curve) InitPubKeyTable(x,y *big.Int) (Precomputed *[37][64*8]uint64) {
	Precomputed = new([37][64 * 8]uint64)

	var r p256Point
	fromBig(r.xyz[0:4], maybeReduceModP(x))
	fromBig(r.xyz[4:8], maybeReduceModP(y))
	sm2p256Mul(r.xyz[0:4], r.xyz[0:4], rr[:])
	sm2p256Mul(r.xyz[4:8], r.xyz[4:8], rr[:])
	r.xyz[8] = 0x0000000000000001
	r.xyz[9] = 0x00000000FFFFFFFF
	r.xyz[10] = 0x0000000000000000
	r.xyz[11] = 0x0000000100000000
	basePoint := []uint64{
		r.xyz[0], r.xyz[1],r.xyz[2],r.xyz[3],
		r.xyz[4],r.xyz[5],r.xyz[6],r.xyz[7],
		r.xyz[8],r.xyz[9],r.xyz[10],r.xyz[11],
	}
	t1 := make([]uint64, 12)
	t2 := make([]uint64, 12)
	copy(t2, basePoint)

	zInv := make([]uint64, 4)
	zInvSq := make([]uint64, 4)
	for j := 0; j < 64; j++ {
		copy(t1, t2)
		for i := 0; i < 37; i++ {
			// The window size is 7 so we need to double 7 times.
			if i != 0 {
				for k := 0; k < 7; k++ {
					sm2p256PointDoubleAsm(t1, t1)
				}
			}
			// Convert the point to affine form. (Its values are
			// still in Montgomery form however.)
			p256Inverse(zInv, t1[8:12])
			sm2p256Sqr(zInvSq, zInv)
			sm2p256Mul(zInv, zInv, zInvSq)

			sm2p256Mul(t1[:4], t1[:4], zInvSq)
			sm2p256Mul(t1[4:8], t1[4:8], zInv)

			copy(t1[8:12], basePoint[8:12])
			// Update the table entry
			copy(Precomputed[i][j*8:], t1[:8])
		}
		if j == 0 {
			sm2p256PointDoubleAsm(t2, basePoint)
		} else {
			sm2p256PointAddAsm(t2, t2, basePoint)
		}
	}
	return
}
func (curve p256Curve) PreScalarMult(Precomputed *[37][64*8]uint64, scalar []byte) (x,y *big.Int) {
	scalarReversed := make([]uint64, 4)
	p256GetScalar(scalarReversed, scalar)

	r := new(p256Point)
	r.p256PreMult(Precomputed,scalarReversed)
	x,y = r.p256PointToAffine()
	return
}