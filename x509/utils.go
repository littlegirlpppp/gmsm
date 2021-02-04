package x509

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"github.com/littlegirlpppp/gmsm/sm2"
	"math/big"
	"reflect"
)

func ReadPrivateKeyFromPem(privateKeyPem []byte, pwd []byte) (*sm2.PrivateKey, error) {
	var block *pem.Block
	block, _ = pem.Decode(privateKeyPem)
	if block == nil {
		return nil, errors.New("failed to decode private key")
	}
	priv, err := ParsePKCS8PrivateKey(block.Bytes)
	return priv.(*sm2.PrivateKey), err
}

func WritePrivateKeyToPem(key *sm2.PrivateKey, pwd []byte) ([]byte, error) {
	//var block *pem.Block
	//der, err := MarshalSm2PrivateKey(key, pwd) //Convert private key to DER format
	//if err != nil {
	//	return nil, err
	//}
	//if pwd != nil {
	//	block = &pem.Block{
	//		Type:  "ENCRYPTED PRIVATE KEY",
	//		Bytes: der,
	//	}
	//} else {
	//	block = &pem.Block{
	//		Type:  "PRIVATE KEY",
	//		Bytes: der,
	//	}
	//}
	//certPem := pem.EncodeToMemory(block)
	return nil, nil
}
var (
	oidPBES1  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 3}  // pbeWithMD5AndDES-CBC(PBES1)
	oidPBES2  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13} // id-PBES2(PBES2)
	oidPBKDF2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12} // id-PBKDF2

	oidKEYMD5    = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 5}
	oidKEYSHA1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	oidKEYSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidKEYSHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}

	oidAES128CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES256CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}

	oidSM2 = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
)

func ReadPublicKeyFromPem(publicKeyPem []byte) (*sm2.PublicKey, error) {
	block, _ := pem.Decode(publicKeyPem)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to decode public key")
	}
	return ParseSm2PublicKey(block.Bytes)
}
func ParseSm2PublicKey(der []byte) (*sm2.PublicKey, error) {
	var pubkey pkixPublicKey

	if _, err := asn1.Unmarshal(der, &pubkey); err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(pubkey.Algo.Algorithm, oidSM2) {
		return nil, errors.New("x509: not sm2 elliptic curve")
	}
	curve := sm2.P256Sm2()
	x, y := elliptic.Unmarshal(curve, pubkey.BitString.Bytes)
	pub := sm2.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}
	return &pub, nil
}
func WritePublicKeyToPem(key *sm2.PublicKey) ([]byte, error) {
	//der, err := MarshalSm2PublicKey(key) //Convert publick key to DER format
	//if err != nil {
	//	return nil, err
	//}
	//block := &pem.Block{
	//	Type:  "PUBLIC KEY",
	//	Bytes: der,
	//}
	//certPem := pem.EncodeToMemory(block)
	return nil, nil
}

func ReadCertificateRequestFromPem(certPem []byte) (*CertificateRequest, error) {
	block, _ := pem.Decode(certPem)
	if block == nil {
		return nil, errors.New("failed to decode certificate request")
	}
	return ParseCertificateRequest(block.Bytes)
}

func CreateCertificateRequestToPem(template *CertificateRequest, signer crypto.Signer) ([]byte, error) {
	der, err := CreateCertificateRequest(rand.Reader, template, signer)
	if err != nil {
		return nil, err
	}
	block := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: der,
	}
	certPem := pem.EncodeToMemory(block)
	return certPem, nil
}

func ReadCertificateFromPem(certPem []byte) (*Certificate, error) {
	block, _ := pem.Decode(certPem)
	if block == nil {
		return nil, errors.New("failed to decode certificate request")
	}
	return ParseCertificate(block.Bytes)
}


// CreateCertificateToPem creates a new certificate based on a template and
// encodes it to PEM format. It uses CreateCertificate to create certificate
// and returns its PEM format.
func CreateCertificateToPem(template, parent *Certificate, pubKey *sm2.PublicKey, signer crypto.Signer) ([]byte, error) {
	//der, err := CreateCertificate(template, parent, pubKey, signer)
	//if err != nil {
	//	return nil, err
	//}
	//block := &pem.Block{
	//	Type:  "CERTIFICATE",
	//	Bytes: der,
	//}
	//certPem := pem.EncodeToMemory(block)
	return nil, nil
}

// todo 新增加的适配用
func ParseSm2CertifateToX509Test(asn1data []byte) (*x509.Certificate, error) {
	sm2Cert, err := ParseCertificate(asn1data)
	if err != nil {
		return nil, err
	}
	return sm2Cert.ToX509Certificate(), nil
}

func (c *Certificate) ToX509Certificate() *x509.Certificate {
	x509cert := &x509.Certificate{
		Raw:                     c.Raw,
		RawTBSCertificate:       c.RawTBSCertificate,
		RawSubjectPublicKeyInfo: c.RawSubjectPublicKeyInfo,
		RawSubject:              c.RawSubject,
		RawIssuer:               c.RawIssuer,

		Signature:          c.Signature,
		SignatureAlgorithm: x509.SignatureAlgorithm(c.SignatureAlgorithm),

		PublicKeyAlgorithm: x509.PublicKeyAlgorithm(c.PublicKeyAlgorithm),
		PublicKey:          c.PublicKey,

		Version:      c.Version,
		SerialNumber: c.SerialNumber,
		Issuer:       c.Issuer,
		Subject:      c.Subject,
		NotBefore:    c.NotBefore,
		NotAfter:     c.NotAfter,
		KeyUsage:     x509.KeyUsage(c.KeyUsage),

		Extensions: c.Extensions,

		ExtraExtensions: c.ExtraExtensions,

		UnhandledCriticalExtensions: c.UnhandledCriticalExtensions,

		//ExtKeyUsage:	[]x509.ExtKeyUsage(c.ExtKeyUsage) ,
		UnknownExtKeyUsage: c.UnknownExtKeyUsage,

		BasicConstraintsValid: c.BasicConstraintsValid,
		IsCA:                  c.IsCA,
		MaxPathLen:            c.MaxPathLen,
		// MaxPathLenZero indicates that BasicConstraintsValid==true and
		// MaxPathLen==0 should be interpreted as an actual maximum path length
		// of zero. Otherwise, that combination is interpreted as MaxPathLen
		// not being set.
		MaxPathLenZero: c.MaxPathLenZero,

		SubjectKeyId:   c.SubjectKeyId,
		AuthorityKeyId: c.AuthorityKeyId,

		// RFC 5280, 4.2.2.1 (Authority Information Access)
		OCSPServer:            c.OCSPServer,
		IssuingCertificateURL: c.IssuingCertificateURL,

		// Subject Alternate Name values
		DNSNames:       c.DNSNames,
		EmailAddresses: c.EmailAddresses,
		IPAddresses:    c.IPAddresses,

		// Name constraints
		PermittedDNSDomainsCritical: c.PermittedDNSDomainsCritical,
		PermittedDNSDomains:         c.PermittedDNSDomains,

		// CRL Distribution Points
		CRLDistributionPoints: c.CRLDistributionPoints,

		PolicyIdentifiers: c.PolicyIdentifiers,
	}

	for _, val := range c.ExtKeyUsage {
		x509cert.ExtKeyUsage = append(x509cert.ExtKeyUsage, x509.ExtKeyUsage(val))
	}

	return x509cert
}

func WritePrivateKeytoMem(key *sm2.PrivateKey, pwd []byte) ([]byte, error) {
	return WritePrivateKeyToPem(key,pwd)
}

func WritePublicKeytoMem(key *sm2.PublicKey, _ []byte) ([]byte, error) {
return WritePublicKeyToPem(key)
}

func CreateCertificateToMem(template, parent *Certificate, pubKey *sm2.PublicKey, privKey *sm2.PrivateKey) ([]byte, error) {
	return CreateCertificateToPem(template,parent,pubKey,privKey)
}

func CreateCertificateRequestToMem(template *CertificateRequest, privKey *sm2.PrivateKey) ([]byte, error) {
    return  CreateCertificateRequestToPem(template,privKey)
}

func ReadPrivateKeyFromMem(data []byte, pwd []byte) (*sm2.PrivateKey, error) {
	return  ReadPrivateKeyFromPem(data,pwd)
}

func ReadPublicKeyFromMem(data []byte, _ []byte) (*sm2.PublicKey, error) {
	return  ReadPublicKeyFromPem(data)
}

func ReadCertificateFromMem(data []byte)(*Certificate,error)  {
	return ReadCertificateFromPem(data)
}

func ParsePKCS8UnecryptedPrivateKey(der []byte) (*sm2.PrivateKey, error) {
	var privKey pkcs8

	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(privKey.Algo.Algorithm, oidSM2) {
		return nil, errors.New("x509: not sm2 elliptic curve")
	}
	return ParseSm2PrivateKey(privKey.PrivateKey)
}

type sm2PrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

func ParseSm2PrivateKey(der []byte) (*sm2.PrivateKey, error) {
	var privKey sm2PrivateKey

	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		return nil, errors.New("x509: failed to parse SM2 private key: " + err.Error())
	}
	curve := sm2.P256Sm2()
	k := new(big.Int).SetBytes(privKey.PrivateKey)
	curveOrder := curve.Params().N
	if k.Cmp(curveOrder) >= 0 {
		return nil, errors.New("x509: invalid elliptic curve private key value")
	}
	priv := new(sm2.PrivateKey)
	priv.Curve = curve
	priv.D = k
	privateKey := make([]byte, (curveOrder.BitLen()+7)/8)
	for len(privKey.PrivateKey) > len(privateKey) {
		if privKey.PrivateKey[0] != 0 {
			return nil, errors.New("x509: invalid private key length")
		}
		privKey.PrivateKey = privKey.PrivateKey[1:]
	}
	copy(privateKey[len(privateKey)-len(privKey.PrivateKey):], privKey.PrivateKey)
	priv.X, priv.Y = curve.ScalarBaseMult(privateKey)
	return priv, nil
}

func MarshalSm2PublicKey(key *sm2.PublicKey) ([]byte, error) {
	var r pkixPublicKey
	var algo pkix.AlgorithmIdentifier

	if(key.Curve.Params()!=sm2.P256Sm2().Params()){
		return nil, errors.New("x509: unsupported elliptic curve")
	}
	algo.Algorithm = oidSM2
	algo.Parameters.Class = 0
	algo.Parameters.Tag = 6
	algo.Parameters.IsCompound = false
	algo.Parameters.FullBytes = []byte{6, 8, 42, 129, 28, 207, 85, 1, 130, 45} // asn1.Marshal(asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301})
	r.Algo = algo
	r.BitString = asn1.BitString{Bytes: elliptic.Marshal(key.Curve, key.X, key.Y)}
	return asn1.Marshal(r)
}


func MarshalSm2PrivateKey(key *sm2.PrivateKey, pwd []byte) ([]byte, error) {

		return MarshalSm2UnecryptedPrivateKey(key)

}


func MarshalSm2UnecryptedPrivateKey(key *sm2.PrivateKey) ([]byte, error) {
	var r pkcs8
	var priv sm2PrivateKey
	var algo pkix.AlgorithmIdentifier

	algo.Algorithm = oidSM2
	algo.Parameters.Class = 0
	algo.Parameters.Tag = 6
	algo.Parameters.IsCompound = false
	algo.Parameters.FullBytes = []byte{6, 8, 42, 129, 28, 207, 85, 1, 130, 45} // asn1.Marshal(asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301})
	priv.Version = 1
	priv.NamedCurveOID = oidNamedCurveP256SM2
	priv.PublicKey = asn1.BitString{Bytes: elliptic.Marshal(key.Curve, key.X, key.Y)}
	priv.PrivateKey = key.D.Bytes()
	r.Version = 0
	r.Algo = algo
	r.PrivateKey, _ = asn1.Marshal(priv)
	return asn1.Marshal(r)
}

