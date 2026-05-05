defmodule CurveTest do
  use ExUnit.Case

  alias EllipticCurve.{Curve, Point, PublicKey, Signature, Ecdsa, PrivateKey}
  alias EllipticCurve.Curve.KnownCurves

  test "testSupportedCurve" do
    newCurve = %Curve{
      name: :secp256k1,
      A: 0x0000000000000000000000000000000000000000000000000000000000000000,
      B: 0x0000000000000000000000000000000000000000000000000000000000000007,
      P: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
      N: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
      G: %Point{
        x: 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        y: 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
      },
      oid: [1, 3, 132, 0, 10]
    }

    privateKey1 = PrivateKey.generate(nil, newCurve)
    publicKey1 = PrivateKey.getPublicKey(privateKey1)

    privateKeyPem = PrivateKey.toPem(privateKey1)
    publicKeyPem = PublicKey.toPem(publicKey1)

    {:ok, privateKey2} = PrivateKey.fromPem(privateKeyPem)
    {:ok, publicKey2} = PublicKey.fromPem(publicKeyPem)

    message = "test"

    signatureBase64 = Ecdsa.sign(message, privateKey2) |> Signature.toBase64()
    {:ok, signature} = Signature.fromBase64(signatureBase64)

    assert Ecdsa.verify?(message, signature, publicKey2)
  end

  test "testAddNewCurve" do
    newCurve = %Curve{
      name: :frp256v1,
      A: 0xF1FD178C0B3AD58F10126DE8CE42435B3961ADBCABC8CA6DE8FCF353D86E9C00,
      B: 0xEE353FCA5428A9300D4ABA754A44C00FDFEC0C9AE4B1A1803075ED967B7BB73F,
      P: 0xF1FD178C0B3AD58F10126DE8CE42435B3961ADBCABC8CA6DE8FCF353D86E9C03,
      N: 0xF1FD178C0B3AD58F10126DE8CE42435B53DC67E140D2BF941FFDD459C6D655E1,
      G: %Point{
        x: 0xB6B3D4C356C139EB31183D4749D423958C27D2DCAF98B70164C97A2DD98F5CFF,
        y: 0x6142E0F7C8B204911F9271F0F3ECEF8C2701C307E8E4C9E183115A1554062CFB
      },
      oid: [1, 2, 250, 1, 223, 101, 256, 1]
    }

    KnownCurves.add(newCurve)

    privateKey1 = PrivateKey.generate(nil, newCurve)
    publicKey1 = PrivateKey.getPublicKey(privateKey1)

    privateKeyPem = PrivateKey.toPem(privateKey1)
    publicKeyPem = PublicKey.toPem(publicKey1)

    {:ok, privateKey2} = PrivateKey.fromPem(privateKeyPem)
    {:ok, publicKey2} = PublicKey.fromPem(publicKeyPem)

    message = "test"

    signatureBase64 = Ecdsa.sign(message, privateKey2) |> Signature.toBase64()
    {:ok, signature} = Signature.fromBase64(signatureBase64)

    assert Ecdsa.verify?(message, signature, publicKey2)
  end

  test "testUnsupportedCurve" do
    newCurve = %Curve{
      name: :brainpoolP256t1,
      A: 0xA9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5374,
      B: 0x662C61C430D84EA4FE66A7733D0B76B7BF93EBC4AF2F49256AE58101FEE92B04,
      P: 0xA9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377,
      N: 0xA9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7,
      G: %Point{
        x: 0xA3E8EB3CC1CFE7B7732213B23A656149AFA142C47AAFBC2B79A191562E1305F4,
        y: 0x2D996C823439C56D7F7B22E14644417E69BCB6DE39D027001DABE8F35B25C9BE
      },
      oid: [1, 3, 36, 3, 3, 2, 8, 1, 1, 8]
    }

    privateKeyPem = PrivateKey.generate(nil, newCurve) |> PrivateKey.toPem()
    publicKeyPem = PrivateKey.generate(nil, newCurve) |> PrivateKey.getPublicKey() |> PublicKey.toPem()

    assert_raise RuntimeError, ~r/Unknown curve/, fn ->
      PrivateKey.fromPem!(privateKeyPem)
    end

    assert_raise RuntimeError, ~r/Unknown curve/, fn ->
      PublicKey.fromPem!(publicKeyPem)
    end
  end
end
