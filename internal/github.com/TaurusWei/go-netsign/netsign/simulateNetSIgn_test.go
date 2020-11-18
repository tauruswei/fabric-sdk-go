package netsign

import (
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"testing"
)

/**
 * @Author: WeiBingtao/13156050650@163.com
 * @Version: 1.0
 * @Description:
 * @Date: 2020/9/17 下午4:30
 */

func TestNetSign_CLoseNetSign(t *testing.T) {
	ns := NetSign{}
	socketFd, ret := ns.OpenNetSign("47.105.180.88", "CNCC123456", 19443)
	if ret!=0{
		fmt.Println("open netsign error")
	}
	p10, ret := ns.GenP10(socketFd, "CN=brilliance", "test", "SM2")
	if ret!=0{
		fmt.Println("generate p10 error")
	}
	
	
	ret= ns.UploadCert(socketFd, "test", p10)
	if ret!=0{
		fmt.Println("upload cert error")
	}
	sign,ret := ns.Sign(socketFd, 0, []byte("hello world"), "test", "sm3")
	if ret!=0{
		fmt.Println("sign error")
	}
	fmt.Println(base64.StdEncoding.EncodeToString(sign))
	ret = ns.Verify(socketFd, 1, []byte("hello world"), sign, "test", "sm3")
	if ret!=0{
		fmt.Println("verify error")
	}
	
}
func TestSignature(t *testing.T){
	signature, _ := base64.StdEncoding.DecodeString(
		"MEUCIQDvUuY3NaImX1wvKd/E5wMn0y2Zwv+okjPmUPNSykOzUgIgXWUKz3rxwV1MOrjrsrP+4aEN8q90avQ25Buxugj2vCw=")
	fmt.Println(signature)
	var sig SM2Signature
	_, err := asn1.Unmarshal(signature, &sig)
	if err!=nil{
		fmt.Println("unmarshal error")
	}
	r, s := sig.R.Bytes(), sig.S.Bytes()
	//sig := make([]byte, len(r)+len(s))
	combine := BytesCombine(r, s)
	fmt.Println(combine)
	fmt.Println(base64.StdEncoding.EncodeToString(combine))
}

