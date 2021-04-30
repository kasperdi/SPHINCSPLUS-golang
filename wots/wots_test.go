package wots

import (
	"testing"
	"crypto/rand"
	"encoding/hex"
	"bytes"
	"../address"
	"../parameters"
	"fmt"
)

// Tests that signed messages can be verified with the correct signature
func TestSignAndVerify(t *testing.T) {
	for i := 0; i < 10; i++ {
		message := make([]byte, parameters.N)
		rand.Read(message)
		SKseed := make([]byte, parameters.N)
		rand.Read(SKseed)
		PKseed := make([]byte, parameters.N)
		rand.Read(SKseed)
		var adrs address.ADRS  // Are 3 needed?

		PK := Wots_PKgen(SKseed, PKseed, &adrs)

		signature := Wots_sign(message, SKseed, PKseed, &adrs)

		pkFromSig := Wots_pkFromSig(signature, message, PKseed, &adrs)
		fmt.Println(hex.EncodeToString(PK))
		fmt.Println(hex.EncodeToString(pkFromSig))
		if(!bytes.Equal(pkFromSig, PK)) {
			t.Errorf("Verification of signed message failed, but was expected to succeed!")
		}
	}
	
}

// Ensures that a wrong key cannot be used to verify a message
func TestSignVerifyWrongKey(t *testing.T) {
	for i := 0; i < 10; i++ {
		message := make([]byte, parameters.N)
		rand.Read(message)
		wrongMessage := make([]byte, parameters.N)
		rand.Read(wrongMessage)
		SKseed := make([]byte, parameters.N)
		rand.Read(SKseed)
		PKseed := make([]byte, parameters.N)
		rand.Read(SKseed)
		var adrs address.ADRS  // Are 3 needed?
		var adrs2 address.ADRS
		var adrs3 address.ADRS

		PK := Wots_PKgen(SKseed, PKseed, &adrs)

		signature := Wots_sign(message, SKseed, PKseed, &adrs2)

		pkFromSig := Wots_pkFromSig(signature, wrongMessage, PKseed, &adrs3)
		if(bytes.Equal(pkFromSig, PK)) {
			t.Errorf("Verification of signed message succeeded, but was expected to fail!")
		}
	}
}

func TestSignFixed(t *testing.T) {
	tmp := make([]byte, parameters.N)
	for i := 0; i < parameters.N; i++ {
		tmp[i] = byte(i);
	}
	SKseed := make([]byte, parameters.N)

	var adrs address.ADRS

	signature := Wots_sign(tmp, SKseed, tmp, &adrs)

	SignatureAsString := hex.EncodeToString(signature)

	expected := "ea659cdc838619b3767c057fdf8e6d99fde2680c5d8517eb06761c0878d40c40598e9511d87b8b3f0b5b19ee1370c1d4fc1db032643e7c6287e6ec5348d514187ae1dd89480cc807ebbec17836c4cb74cfde80d776ec5bc0f74e34ca5699f7a07dc38dff8ba5d0fa7c491abcc648e64947b2574edbb3c7e56634d43f23d8fff2b878c2bee9190c6f2adfeac33971c7340019792b9bd404483866f90239ba89beea8e68bb75870db08d76410fd0853e92be90db60ec0384ce428d3830c69887863dbab930d7054bc3e738bb294c16a29a7934747ad382dd5048d7010fae94c2fc0cae16181a81c53bbe003466b95731da9cd32d54fee3b71553865fbae99281519847096331cb49f807ec31d930c8593dd676aa08927d303a75b74dfdbfff267d45f6a942d7d9debeb81ce091bbca5cbe4f2b9425c8d3fb65f64df46806a0070eadbee707c32cc8c2c69316f0fba744aec4214cbfaa1ce54695c996fd5298f8c59843bf4a1775efe02073abe090711e23745be3f5d9e9c64614d0b13ec220e4fcef74bfd802c16ad75c336d00c7bab1464bb803fb1265998469511860f43bf499ab0126569f1f2c9d357db52a4a81dd5c3e4883e27176df1476010d6d3f706b6be4623cbee175879a21d31fe91c7457c4a3b63c279608e03339a42eb2381ef856037d2fc8f090ccd8e8dd1e96e3925997704bb61d9f6a9966088541d09d4ea12b0194ac03c6f28e39da81f77884abe4471447dc27ede59b3e5eaf6d28b27c615e1facecfb6785bf7828658c8c27b80dded6791762572c548960eb5e962226a255f60e628aad594ed690d944a171a3647e05f3668fb434b859c10e37180ab649c662a55789e0ed1b9a620c15ca11f205223a82bbd193d2f7faa47ca8e93e475ffb6baf5348f81c04137703467b6d98c79ae2bae9297c6d508d0766d3dd0f2679d313cf6e545fe9be0971fd7f2df68c664c1570e1309537df51dc98c1abc1bf5bdd99bc2b12fd0156ddc974fc4d1159d7649cd32328a2c7b74777809e09ae217f2ce728ab2d184d78f28ae7de4371a282ee87e9c1e648b09bb1a9246c73936751d1678271841c5a6be459710590ae743a19908e70d3f90412d28f952547c3f648c23c1281ee57f92119749f29d0c808492a76153fb1887dab6c9d4c5e35bff8054a916a7669558821da0013971636fbeb1e436100ea494b884f1cbaaaae37de26a3d47077ba3162ade6274edfcab5e54d79c8e07409fd943e1f6dbaa9697bd7acbbeff0694d299243f3e69ed3ea3b59d441b4e682e75a2868ba12c4d2a5d18f7ff31baade47d54a6ed6012cd800821c5218af043fa4ea48851d8745299f32575ea188c0377ff9f7d121adc2b402b8552e4df0e5f58d562f2c70c2a63306e35feea4b9f271d1730ebe4b74857fd61c109bace8f3b5a61c451abaf377c3bcbf9f7e4f34575d515e44b5671642c192be47a2fdd6d20db6e9f57d273b85ba4d86337ca9521cfbfc9d7de611f4679db07c06b4848da63a4dc4599adfdadb32f2da61d78b3bc6a0f948b28e10ff18cbd42ca277ff48918ae6de63b5e6f780bb7f1bf933646b70c3fbac63d9adc7e1ae696c0e3f494fc8fa2ef49216f5f063ac801273e9e040c7fb239d81e72093f9f23cab52b5a0a98c3111d8ae26f28bb7d51740ba2f90734d9d9663ce514395d69ce206c98b2f464d59f2268c582cd29519b0aa1bc66de5fd2425807ab22e104b9481c9ea4e4b7bc1867490310442b15284cc00691951a0c913a7e05de56180ed5e9614653732d486a254533df52cfdca4830e1c7a3981941e497fc70286090e68e006a9a2cb03778ae813c2abde9f7da8c55fdad0aa1b490e1d13f0dbbe906967906a1323dd77364dcb5c69c337248514e225503cca96a1d18122764aa5141bb998c8e956c82b6cef2eec501f07433b660dd116c82529423ca846f3604b810da253ed5c4b40fbfcf453cd1de0e696cb02af6be07795d44fd65fb3f5140f685c2f5a40f7f0d3f5858aa76242df0da1777df6e8fba90cf0e475e3dca6993a3281c67a1ef0dbd2dd1e823bc417710b4a45387eaa74a7e8554ed2083b824edb64e0a23b77fc746378f61e15257ff893970975460326e7ed262842f07615348b1fdb854bddb98546abc8a5d9fe2f55c9eee3809efcf1f5e8c31c800cf99418aae42167a3749af073102c60b39f9ac14c52311722d188a9f5e980a04602a541da9c9a6c3ae2f787f6827225a19dd10e10e3f1e5937edb3dac6b0b0bf0a90e3c36cd79c895b19d7a1cd5fd3fefc3b9f44fb447f989fe3922e18493bc4b7bf7812afb14c2f442a24549ca27f511cf21dccd63140f39a94d36a4b69194f7fc63bbcc2e5b19c80a980c69fb472ccf48e65c0207a4145cd1065cca3614965d8cb25d5314e1a563408962b8c7c03472c176aa11138730b74be62c21b67fb941301f052527a0d0e2cb65f2228e2dbe9195c9e508a8c7abbaf2aa250ca723daba7d17c0b8b5f531ad1ea07255b46323e648f9261c8681c17a454cf63ec5c7570f93cb4f67d36fc1dde9aa3eb25a3edca76c8807bfa6028c287a638768f61d4f66bef027e9c859ed36bfb55b753faa3a57d7c3b30cf0d5955b5ca047dab25c5c64a5baa49ff0f54b7d9771ae0dcb1101d54e6fcf88e0da898f27b686a5534405e98aef342644dcd5c7c0b997aeb4a8ca2ab04cb10954f122ac1c25d6cb21a97e95beefe4e0f72764507f8fb1a3fa7bcea7a4c51a18268258723a1bd93306e3881ff69a804ea81b4aeab8e550d82862671ab67ff3d4c743d5ee1d8cf6d2583f174eda1e47020ef98f36e61ff90f5aa460c93e81dc6aee854432f14c9162ca3404752a15ed6438890af984f5580dfa4c28a58bb26335537152768b4297bf2d42a59834806a23ea5ed9b9c8bb2c9775f34170c780e66f46fadaa12fe32c3b59adf0a3f37d971f47617e4ba7df3292caa4dff9320eab865fd09c73b2035acbfac116669e30e894e5b0c7693fe3138250a7dca2d1e29d24e607f5bbe4a0b2686"

	if SignatureAsString != expected {
		t.Errorf("Error: Got %s", SignatureAsString)
	}

}