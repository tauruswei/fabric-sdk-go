package utils

/**
 * @Author: WeiBingtao/13156050650@163.com
 * @Version: 1.0
 * @Description:
 * @Date: 2020/10/7 下午8:54
 */
import "github.com/hyperledger/fabric-sdk-go/internal/github.com/tjfoc/gmsm/sm2"

// DERToSM2Certificate converts der to sm2
func DERToSM2Certificate(asn1Data []byte) (*sm2.Certificate, error) {
	return sm2.ParseCertificate(asn1Data)
}