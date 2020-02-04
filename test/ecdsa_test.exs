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
end
