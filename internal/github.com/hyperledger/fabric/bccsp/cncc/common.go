package cncc

/**
 * @Author: WeiBingtao/13156050650@163.com
 * @Version: 1.0
 * @Description:
 * @Date: 2020/9/15 上午11:23
 */
import (
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/TaurusWei/go-netsign/netsign"
	"strconv"
)

func OpenNetSign(ip, password string,port int) (socketFd int, ns *netsign.NetSign) {
	netsign := netsign.NetSign{}
	socketFd, ret := netsign.OpenNetSign(ip, password, port)
	
	if ret != 0 {
		logger.Errorf("open netsign server error")
	}
	
	return socketFd, &netsign
}

func (csp *Impl) getSession() (session *NetSignSesssion) {
	select {
	case session = <-csp.Sessions:
		logger.Debugf("Reusing existing netsign socket fd %d\n", session.NS_sesion)
	default:
		// 如果没有可以使用的会话句柄，会打开签名服务器
		var socketFd int
		var ns NetSignSesssion
		var ret int
		netsign := netsign.NetSign{}
		for _, netSignConfig := range BJ_NetSignConfig {
			
			ip := netSignConfig.Ip
			
			passwd := netSignConfig.Passwd
			
			port, err := strconv.Atoi(netSignConfig.Port)
			if err != nil {
				panic("Get port error !")
			}
			
			socketFd, ret = netsign.OpenNetSign(ip, passwd, port)
			if ret != 0 {
				logger.Errorf("LOGGER-CONN-SIGNAGENT-FAIL: open netsign err: ip [%s], port [%d], passwd [%s]", ip, port, passwd)
				continue
			}
			ns = NetSignSesssion{netSignConfig, socketFd}
			break
		}
		logger.Debugf("Created new netsign session %d\n", socketFd)
		session = &ns
	}
	return session
	
}

func (csp *Impl) returnSession(session *NetSignSesssion) {
	select {
	case csp.Sessions <- session:
	default:
		csp.netsign.CloseNetSign(session.NS_sesion)
	}
}




