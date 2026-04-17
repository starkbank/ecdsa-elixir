defmodule SignatureTest do
  use ExUnit.Case

  alias EllipticCurve.{PrivateKey, Ecdsa, Signature}

  test "testDerConversion" do
    privateKey = PrivateKey.generate()
    message = "This is a text message"

    signature1 = Ecdsa.sign(message, privateKey)

    der = Signature.toDer(signature1)
    {:ok, signature2} = Signature.fromDer(der)

    assert signature1.r == signature2.r
    assert signature1.s == signature2.s
  end

  test "testBase64Conversion" do
    privateKey = PrivateKey.generate()
    message = "This is a text message"

    signature1 = Ecdsa.sign(message, privateKey)

    base64 = Signature.toBase64(signature1)

    {:ok, signature2} = Signature.fromBase64(base64)

    assert signature1.r == signature2.r
    assert signature1.s == signature2.s
  end

  test "testUniqueness" do
    privateKey = PrivateKey.generate()
    message = "This is a text message"

    signature1 = Ecdsa.sign(message, privateKey)
    signature2 = Ecdsa.sign(message, privateKey)

    assert Signature.toBase64(signature1) != Signature.toBase64(signature2)
  end
end
