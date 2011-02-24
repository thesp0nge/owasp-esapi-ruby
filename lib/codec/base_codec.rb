#
# Case Codec class
# This base class handles several areas need by sub codecs
#

# Extend Numbers and add a to_hex method for convience
class Fixnum
  def to_h
    to_s(16)
  end
end
class Bignum
  def to_h
    to_s(16)
  end
end

module Owasp
  module Esapi
    module Codec
      class BaseCodec
        START_CODE_POINT = 0x000
        END_CODE_POINT = 0x10fff
        # a List of Hex codes that cover non alpha numeric values
        @@hex_codes = []
        for c in (0..255) do
          if (c >= 0x30 and c <= 0x39) or (c >= 0x41 and c <= 0x5A) or (c >= 0x61 and c <= 0x7A)
            @@hex_codes[c] = nil
          else
            @@hex_codes[c] = c.to_h
          end
        end
=begin
  immune is expecting an array of safe characters which are immune form encoding
  input is the data to encode.
  returnt eh encoded form of the data
=end
        def encode(immune, input)
          encoded_string = ''
          encoded_string.encode!(Encoding::UTF_8)
          input.encode(Encoding::UTF_8).chars do |c|
            encoded_string << encode_char(immune,c)
          end
          encoded_string
        end
=begin
  sub classes should implement this method to mark how to encode a single character
=end
        def encode_char(immune, input)
          input
        end
=begin
  helper method for codecs to get the hex value of a character
=end
        def hex(c)
          return nil if c.nil?
          b = c[0].ord
          if b < 0xff
            @@hex_codes[b]
          else
            b.to_h
          end
        end
=begin
  input is the data you wish to decode
  decode the data
=end
        def decode(input)
          decoded_string = ''
          seekable = PushableString.new(input)
          while seekable.next?
            t = decode_char(seekable)
            if t.nil?
              decoded_string << seekable.next
            else
              decoded_string << t
            end
          end
          decoded_string
        end
=begin
  input is a PushableString
  subclasses should override this method
=end
        def decode_char(input)
          input
        end
=begin
  basic min funtion
=end
        def min(a,b)
          if a > b
            return b
          else
            return a
          end
        end

      end
    end
  end
end