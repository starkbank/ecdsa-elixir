defmodule PublicKeyTest do
  use ExUnit.Case

  alias EllipticCurve.{PrivateKey, PublicKey}

  test "pem conversion" do
    privateKey = PrivateKey.generate()
    publicKey1 = PrivateKey.getPublicKey(privateKey)

    pem = PublicKey.toPem(publicKey1)

    {:ok, publicKey2} = PublicKey.fromPem(pem)

    assert publicKey1.point.x == publicKey2.point.x
    assert publicKey1.point.y == publicKey2.point.y
    assert publicKey1.curve.name == publicKey2.curve.name
  end

  test "der conversion" do
    privateKey = PrivateKey.generate()
    publicKey1 = PrivateKey.getPublicKey(privateKey)

    der = PublicKey.toDer(publicKey1)

    {:ok, publicKey2} = PublicKey.fromDer(der)

    assert publicKey1.point.x == publicKey2.point.x
    assert publicKey1.point.y == publicKey2.point.y
    assert publicKey1.curve.name == publicKey2.curve.name
  end

  test "string conversion" do
    privateKey = PrivateKey.generate()
    publicKey1 = PrivateKey.getPublicKey(privateKey)

    string = PublicKey.toString(publicKey1)

    {:ok, publicKey2} = PublicKey.fromString(string)

    assert publicKey1.point.x == publicKey2.point.x
    assert publicKey1.point.y == publicKey2.point.y
    assert publicKey1.curve.name == publicKey2.curve.name
  end
end
