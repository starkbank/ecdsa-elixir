defmodule EllipticCurve.Point do
  @doc """
  Holds point data. Is usually handled internally by the library and serves only as detailed information to the end-user.

  Parameters:
  - x [integer]: first point coordinate;
  - y [integer]: first point coordinate;
  - z [integer]: first point coordinate (used only in Jacobian coordinates);
  """
  defstruct [:x, :y, z: 0]

  def isAtInfinity?(p) do
    p.y == 0
  end

end
