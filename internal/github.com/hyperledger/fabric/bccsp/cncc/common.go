package cncc

/**
 * @Author: WeiBingtao/13156050650@163.com
 * @Version: 1.0
 * @Description:
 * @Date: 2020/9/15 上午11:23
 */
import (
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp/netsign"
	"strconv"
)

func OpenNetSign(ip, password string, port int) (socketFd int, ns *netsign.NetSign) {
	netsign := netsign.NetSign{}
	socketFd, ret := netsign.OpenNetSign(ip, password, port)

	if ret != 0 {
		logger.Errorf("open netsign server error,fd=%d ret=%d", socketFd, ret)
	}

	return socketFd, &netsign
}

//func (csp *Impl) findPKCS11Lib() (string, int, string) {
//	ip, port, password := csp.opts.Ip, csp.opts.Port, csp.opts.Password
//	if ip == "" || port == 0 || password == "" {
//		ip, port, password = FindPKCS11Lib()
//	}
//	return ip, port, password
//}

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
		var ALL_NetSignConfig []*NetSignConfig
		for _, v := range csp.BJ_NetSignConfig {
			ALL_NetSignConfig = append(ALL_NetSignConfig, v)
		}
		for _, v := range csp.SH_NetSignConfig {
			ALL_NetSignConfig = append(ALL_NetSignConfig, v)
		}
		for _, netSignConfig := range ALL_NetSignConfig {

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
			logger.Debugf("Created new netsign session %d\n", socketFd)
			session = &ns
			break
		}
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
