defmodule EllipticCurve.Utils.Point do

  alias EllipticCurve.Utils.Point.Data

  def isAtInfinity?(p) do
    p.y == 0
  end

end
