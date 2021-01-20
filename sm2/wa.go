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
	p256            p256Curve
	p256Precomputed *[37][64 * 8]uint64
	precomputeOnce  sync.Once
)
func initP256() {
	// See FIPS 186-3, section D.2.3
	p256.CurveParams = &elliptic.CurveParams{Name: "SM2-P-256"}
	p256.P, _ = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
	p256.N, _ = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
	p256.B, _ = new(big.Int).SetString("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16)
	p256.Gx, _ = new(big.Int).SetString("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
	p256.Gy, _ = new(big.Int).SetString("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16)
	p256.BitSize = 256
}

func initAll() {
	initP256()
}

// P256 returns a Curve which implements sm2 curve.
//
// The cryptographic operations are implemented using constant-time algorithms.
func P256() elliptic.Curve {
	initonce.Do(initAll)
	return p256
}
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
	c := P256()

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
	if in.Cmp(p256.P) < 0 {
		return in
	}
	return new(big.Int).Mod(in, p256.P)
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
