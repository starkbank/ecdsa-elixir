defmodule EllipticCurve.Point do
  @doc """
  Holds point data. Is usually handled internally by the library and serves only as detailed information to the end-user.

  Parameters:
  - `:x` [integer]: first point coordinate;
  - `:y` [integer]: second point coordinate;
  - `:z` [integer]: third point coordinate (used only in Jacobian coordinates);
  """
  defstruct [:x, :y, z: 0]

  def isAtInfinity?(%__MODULE__{y: y}) do
    y == 0
  end
end
