package csp

import (
	"fmt"
	"testing"

	"gopkg.in/tylerb/is.v1"
)

func TestKey(t *testing.T) {
	is := is.New(t)

	provs, err := EnumProviders()
	is.NotZero(provs)

	ctx, err := AcquireCtx("TestGoCryptoAPIContainer", provs[0].Name, provs[0].Type, 0)
	is.NotErr(err)
	defer ctx.Close()

	k1, err := ctx.Key(AtSignature)
	is.Nil(err)
	defer k1.Close()

	k2, err := ctx.Key(AtKeyExchange)
	is.Nil(err)
	defer k2.Close()
}

func TestKeyGenSymmetric(t *testing.T) {
	is := is.New(t)

	prov, err := FindProvider(ProvGost2012_512)
	is.NotErr(err)
	is.NotNil(prov)

	ctx, err := AcquireCtx(Container("TestGoCryptoAPIContainerNew"), prov.Name, prov.Type, CryptNewKeyset)
	is.NotErr(err)
	defer ctx.Close()

	eKey, err := ctx.GenKey(G28147, KeyExportable)
	is.NotErr(err)
	defer eKey.Close()
}

func TestKeyImportExport(t *testing.T) {
	is := is.New(t)

	prov, err := FindProvider(ProvGost2012)
	is.NotErr(err)
	is.NotNil(prov)

	// получатель
	ctxSender, err := AcquireCtx(Container("TestGoCryptoAPIContainer256_1"), prov.Name, prov.Type, 0)
	is.NotErr(err)
	defer ctxSender.Close()

	keySender, err := ctxSender.Key(AtKeyExchange)
	is.Nil(err)
	defer keySender.Close()

	// отправитель
	ctxResponder, err := AcquireCtx(Container("TestGoCryptoAPIContainer256"), prov.Name, prov.Type, 0)
	is.NotErr(err)
	defer ctxResponder.Close()

	keyResponder, err := ctxResponder.Key(AtKeyExchange)
	is.Nil(err)
	defer keyResponder.Close()

	// получаем публичный ключ получателя в виде последовательности бит
	keyResponderBin, err := keyResponder.ExportPublicKey()
	is.Nil(err)

	fmt.Printf("%v\n", keyResponderBin)

	// генерируем ключ согласования
	agreeKey, err := keySender.ImportKey(keyResponderBin)
	is.NotErr(err)

	// генерируем ключ
	eKey, err := ctxResponder.GenKey(G28147, KeyExportable)
	is.NotErr(err)
	defer eKey.Close()

	exportableKey, err := agreeKey.ExportSessionKey(eKey)
	is.NotErr(err)

	exportedKey, err := agreeKey.ImportKey(exportableKey)
	is.NotErr(err)

	is.Equal(exportableKey, exportedKey)
}
