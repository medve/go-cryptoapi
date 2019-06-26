package csp

import (
	"testing"

	"gopkg.in/tylerb/is.v1"
)

func TestDecrypt(t *testing.T) {
	is := is.New(t)

	prov, err := FindProvider(ProvGost2012_512)
	is.NotErr(err)
	is.NotNil(prov)

	ctx, err := AcquireCtx("TestGoCryptoAPIContainer", prov.Name, prov.Type, 0)
	is.NotErr(err)
	defer ctx.Close()

	eKey, err := ctx.GenKey(G28147, KeyExportable)
	is.NotErr(err)
	is.NotNil(eKey)
	defer eKey.Close()

	iv, err := eKey.GetInitializationVector()
	is.NotErr(err)
	is.NotNil(iv)

	keyCopy, err := eKey.DuplicateKey()
	is.NotErr(err)
	is.NotNil(keyCopy)
	defer keyCopy.Close()

	err = keyCopy.SetInitializationVector(iv)
	is.NotErr(err)

	data := []byte("12345678test text")
	encryptedText, err := ctx.Encrypt(eKey, data)

	is.NotErr(err)
	is.NotNil(encryptedText)

	decryptedText, err := ctx.Decrypt(keyCopy, encryptedText)

	is.NotErr(err)
	is.Equal(decryptedText, data)
}
