package sm2

import "math/big"

// Functions implemented in sm2p256_amd64.s
// Montgomery multiplication modulo P256
func sm2p256Mul(res, in1, in2 []uint64)


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
//precompute public key table
func  InitPubKeyTable(x,y *big.Int) (Precomputed *PCom) {
	Precomputed = new(PCom)

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
