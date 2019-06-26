package csp

import (
	"testing"

	"gopkg.in/tylerb/is.v1"
)

func TestGetBufferSize(t *testing.T) {
	is := is.New(t)

	prov, err := FindProvider(ProvGost2012_512)
	is.NotErr(err)
	is.NotNil(prov)

	ctx, err := AcquireCtx("TestGoCryptoAPIContainer", prov.Name, prov.Type, 0)
	is.NotErr(err)
	defer ctx.Close()

	eKey, err := ctx.GenKey(G28147, KeyExportable)
	is.NotErr(err)
	defer eKey.Close()

	data := []byte("test text")
	res, err := ctx.GetBufferSize(eKey, data)

	is.NotErr(err)
	is.Equal(res, 9)

}

func TestEncrypt(t *testing.T) {
	is := is.New(t)

	prov, err := FindProvider(ProvGost2012_512)
	is.NotErr(err)
	is.NotNil(prov)

	ctx, err := AcquireCtx("TestGoCryptoAPIContainer", prov.Name, prov.Type, 0)
	is.NotErr(err)
	defer ctx.Close()

	//TODO derive key and check static result
	eKey, err := ctx.GenKey(G28147, KeyExportable)
	is.NotErr(err)
	defer eKey.Close()

	data := []byte("test text")
	res, err := ctx.Encrypt(eKey, data)

	is.NotErr(err)
	is.NotNil(res)
	is.NotEqual(res, data)

}
