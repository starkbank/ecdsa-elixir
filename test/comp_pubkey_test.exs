defmodule CompPubKeyTest do
  use ExUnit.Case

  alias EllipticCurve.{PrivateKey, PublicKey}

  @tag timeout: 600_000
  test "testBatch" do
    Enum.each(1..100, fn _ ->
      privateKey = PrivateKey.generate()
      publicKey = PrivateKey.getPublicKey(privateKey)
      publicKeyString = PublicKey.toCompressed(publicKey)

      recoveredPublicKey = PublicKey.fromCompressed(publicKeyString, publicKey.curve)

      assert publicKey.point.x == recoveredPublicKey.point.x
      assert publicKey.point.y == recoveredPublicKey.point.y
    end)
  end

  test "testFromCompressedEven" do
    publicKeyCompressed = "0252972572d465d016d4c501887b8df303eee3ed602c056b1eb09260dfa0da0ab2"
    publicKey = PublicKey.fromCompressed(publicKeyCompressed)
    assert PublicKey.toPem(publicKey) == "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEUpclctRl0BbUxQGIe43zA+7j7WAsBWse\nsJJg36DaCrKIdC9NyX2e22/ZRrq8AC/fsG8myvEXuUBe15J1dj/bHA==\n-----END PUBLIC KEY-----\n"
  end

  test "testFromCompressedOdd" do
    publicKeyCompressed = "0318ed2e1ec629e2d3dae7be1103d4f911c24e0c80e70038f5eb5548245c475f50"
    publicKey = PublicKey.fromCompressed(publicKeyCompressed)
    assert PublicKey.toPem(publicKey) == "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEGO0uHsYp4tPa574RA9T5EcJODIDnADj1\n61VIJFxHX1BMIg0B4cpBnLG6SzOTthXpndIKpr8HEHj3D9lJAI50EQ==\n-----END PUBLIC KEY-----\n"
  end

  test "testToCompressedEven" do
    {:ok, publicKey} = PublicKey.fromPem("-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEUpclctRl0BbUxQGIe43zA+7j7WAsBWse\nsJJg36DaCrKIdC9NyX2e22/ZRrq8AC/fsG8myvEXuUBe15J1dj/bHA==\n-----END PUBLIC KEY-----")
    publicKeyCompressed = PublicKey.toCompressed(publicKey)
    assert publicKeyCompressed == "0252972572d465d016d4c501887b8df303eee3ed602c056b1eb09260dfa0da0ab2"
  end

  test "testToCompressedOdd" do
    {:ok, publicKey} = PublicKey.fromPem("-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEGO0uHsYp4tPa574RA9T5EcJODIDnADj1\n61VIJFxHX1BMIg0B4cpBnLG6SzOTthXpndIKpr8HEHj3D9lJAI50EQ==\n-----END PUBLIC KEY-----")
    publicKeyCompressed = PublicKey.toCompressed(publicKey)
    assert publicKeyCompressed == "0318ed2e1ec629e2d3dae7be1103d4f911c24e0c80e70038f5eb5548245c475f50"
  end
end
