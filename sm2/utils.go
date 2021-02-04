package sm2

import (
	"encoding/asn1"
	"math/big"
)


func SignDigitToSignData(r, s *big.Int) ([]byte, error) {
	return asn1.Marshal(sm2Signature{r, s})
}

func SignDataToSignDigit(sign []byte) (*big.Int, *big.Int, error) {
	var sm2Sign sm2Signature

	_, err := asn1.Unmarshal(sign, &sm2Sign)
	if err != nil {
		return nil, nil, err
	}
	return sm2Sign.R, sm2Sign.S, nil
}
