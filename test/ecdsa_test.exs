defmodule EcdsaTest do
  use ExUnit.Case

  alias EllipticCurve.{PrivateKey, Ecdsa}

  test "verify right message" do
    privateKey = PrivateKey.generate()
    publicKey = PrivateKey.getPublicKey(privateKey)

    message = "This is the right message"

    signature = Ecdsa.sign(message, privateKey)

    assert Ecdsa.verify?(message, signature, publicKey)
  end

  test "verify wrong message" do
    privateKey = PrivateKey.generate()
    publicKey = PrivateKey.getPublicKey(privateKey)

    message1 = "This is the right message"
    message2 = "This is the wrong message"

    signature = Ecdsa.sign(message1, privateKey)

    assert !Ecdsa.verify?(message2, signature, publicKey)
  end
end
