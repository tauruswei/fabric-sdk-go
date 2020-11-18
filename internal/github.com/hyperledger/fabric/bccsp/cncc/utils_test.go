package cncc

import (
	"encoding/base64"
	"fmt"
	"github.com/tjfoc/gmsm/sm2"
	"sync"
	"testing"
	"time"
)

/**
 * @Author: WeiBingtao/13156050650@163.com
 * @Version: 1.0
 * @Description:
 * @Date: 2020/9/15 下午12:01
 */


var (
	myMap = make(map[int]int, 10)
	lock sync.Mutex
)
func test(n int) {
	
	
	res := 1
	for i := 1; i <= n; i++ {
		res *= i
	}
	
	
	//这里我们将 res 放入到 myMap
	//加锁
	lock.Lock()
	myMap[n] = res //concurrent map writes?
	//解锁
	lock.Unlock()
}
func TestChannel(*testing.T) {
	
	// 我们这里开启多个协程完成这个任务[200 个]
	for i := 1; i <= 200; i++ {
		go test(i)
		
	}
	
	//休眠 10 秒钟【第二个问题 】
	time.Sleep(time.Second * 10)
	
	//这里我们输出结果,变量这个结果
	lock.Lock()
	for i, v := range myMap {
		fmt.Printf("map[%d]=%d\n", i, v)
	}
	lock.Unlock()
}

func TestParseP10(*testing.T) {
	p10:="MIHXMHwCAQAwHDEaMBgGA1UEAwwRc20yX2NhcGlfZ2VuXzIwNDgwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAAR62m/6e+iPYvHRpPzLxLDCapIqNq6lfWYlr8i9+d7RyfcC8jD4Mg9NKVqvqwdRiYwj4mXZoGkPw9+McSTMdOT3MAwGCCqBHM9VAYN1BQADSQAwRgIhAIf2FLo9iTkafJn1ikw66M6oXsd8NRHAGLFlCUqzIk5dAiEA7MfoosNH5NE5O6RvKv4xeKgIgNni2hAGTm8r3jMlFWQ="
	decodeString, err := base64.StdEncoding.DecodeString(p10)
	if(nil!=err){
		fmt.Println(err.Error())
	}
	request, err := sm2.ParseCertificateRequest(decodeString)
	if(nil!=err){
		fmt.Println(err.Error())
	}
	fmt.Println(request)
	
}
func TestRandStringInt(t *testing.T) {
	id := RandStringInt()
	printf, _:= fmt.Printf("SM2SignKey%s", id)
	fmt.Println(printf)
	fmt.Println(len([]byte("SM2SignKey32200623148637695498943547498760925770749")))
}

func TestFindPKCS11Lib(t *testing.T) {
	
	lib, i, s := FindPKCS11Lib()
	
	fmt.Println(lib)
	fmt.Println(i)
	fmt.Println(s)
}