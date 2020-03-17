defmodule EllipticCurve.PrivateKey.Data do
  @doc """
  Holds private key data. Is usually extracted from .pem files.

  Parameters:
  - secret [integer]: private key secret number;
  - curve [%EllipticCurve.Curve.Data]: private key curve information;
  """
  defstruct [:secret, :curve]
end
