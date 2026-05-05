defmodule SignatureWithRecoveryIdTest do
  use ExUnit.Case

  alias EllipticCurve.{PrivateKey, Ecdsa, Signature}

  test "testDerConversion" do
    privateKey = PrivateKey.generate()
    message = "This is a text message"

    signature1 = Ecdsa.sign(message, privateKey)

    der = Signature.toDer(signature1, withRecoveryId: true)
    {:ok, signature2} = Signature.fromDer(der, recoveryByte: true)

    assert signature1.r == signature2.r
    assert signature1.s == signature2.s
    assert signature1.recoveryId == signature2.recoveryId
  end

  test "testBase64Conversion" do
    privateKey = PrivateKey.generate()
    message = "This is a text message"

    signature1 = Ecdsa.sign(message, privateKey)

    base64 = Signature.toBase64(signature1, withRecoveryId: true)

    {:ok, signature2} = Signature.fromBase64(base64, recoveryByte: true)

    assert signature1.r == signature2.r
    assert signature1.s == signature2.s
    assert signature1.recoveryId == signature2.recoveryId
  end
end
