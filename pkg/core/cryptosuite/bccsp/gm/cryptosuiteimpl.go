package gm

/**
 * @Author: WeiBingtao/13156050650@163.com
 * @Version: 1.0
 * @Description:
 * @Date: 2020/9/23 下午3:29
 */

import (
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
	bccspSw "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp/factory/gm"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp/gm"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/logging"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/cryptosuite/bccsp/wrapper"
	"github.com/pkg/errors"
)

var logger = logging.NewLogger("fabsdk/core")

//GetSuiteByConfig returns cryptosuite adaptor for bccsp loaded according to given config
func GetSuiteByConfig(config core.CryptoSuiteConfig) (core.CryptoSuite, error) {
	// TODO: delete this check?
	if config.SecurityProvider() != "gm" {
		return nil, errors.Errorf("Unsupported BCCSP Provider: %s", config.SecurityProvider())
	}
	
	opts := getOptsByConfig(config)
	bccsp, err := getBCCSPFromOpts(opts)
	if err != nil {
		return nil, err
	}
	return wrapper.NewCryptoSuite(bccsp), nil
}

//GetSuiteWithDefaultEphemeral returns cryptosuite adaptor for bccsp with default ephemeral options (intended to aid testing)
func GetSuiteWithDefaultEphemeral() (core.CryptoSuite, error) {
	opts := getEphemeralOpts()
	
	bccsp, err := getBCCSPFromOpts(opts)
	if err != nil {
		return nil, err
	}
	return wrapper.NewCryptoSuite(bccsp), nil
}

func getBCCSPFromOpts(config *bccspSw.GmOpts) (bccsp.BCCSP, error) {
	f := &bccspSw.GMFactory{}
	
	csp, err := f.Get(config)
	if err != nil {
		return nil, errors.Wrapf(err, "Could not initialize BCCSP %s", f.Name())
	}
	return csp, nil
}

// GetSuite returns a new instance of the software-based BCCSP
// set at the passed security level, hash family and KeyStore.
func GetSuite(securityLevel int, hashFamily string, keyStore bccsp.KeyStore) (core.CryptoSuite, error) {
	bccsp, err := gm.New(securityLevel, hashFamily, keyStore)
	if err != nil {
		return nil, err
	}
	return wrapper.NewCryptoSuite(bccsp), nil
}

//GetOptsByConfig Returns Factory opts for given SDK config
func getOptsByConfig(c core.CryptoSuiteConfig) *bccspSw.GmOpts {
	opts := &bccspSw.GmOpts{
		HashFamily: c.SecurityAlgorithm(),
		SecLevel:   c.SecurityLevel(),
		FileKeystore: &bccspSw.FileKeystoreOpts{
			KeyStorePath: c.KeyStorePath(),
		},
		//Ephemeral: c.Ephemeral(),
	}
	logger.Debugf("Initialized SW cryptosuite11111, %v", c.SecurityAlgorithm())
	
	return opts
}

func getEphemeralOpts() *bccspSw.GmOpts {
	opts := &bccspSw.GmOpts{
		HashFamily: "SHA256",
		SecLevel:   256,
		Ephemeral:  true,
	}
	logger.Debug("Initialized ephemeral SW cryptosuite with default opts")
	
	return opts
}
