defmodule EllipticCurve.PublicKey.Data do
  @doc """
  Holds public key data. Is usually extracted from .pem files or from the private key itself.

  Parameters:
  - point [%EllipticCurve.Utils.Point]: public key point data;
  - curve [%EllipticCurve.Curve.Data]: public key curve information;
  """
  defstruct [:point, :curve]
end
