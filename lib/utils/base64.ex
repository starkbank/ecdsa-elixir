defmodule Base64 do
  @moduledoc false

  def decode(string) do
    Base.decode64!(string)
  end

  def encode(string) do
    Base.encode64!(string)
  end
end
