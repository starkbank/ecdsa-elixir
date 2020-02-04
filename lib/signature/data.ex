defmodule EllipticCurve.Signature.Data do
  @doc """
  Holds signature data. Is usually extracted from base64 strings.

  Parameters:
  - r [integer]: first signature number;
  - s [integer]: second signature number;
  """
  defstruct [:r, :s]
end
