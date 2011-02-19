#
# Case Codec class
# This base class handles several areas need by sub codecs
#
module Owasp
  module Esapi
    module Codec
      class BaseCodec
        # a List of Hex codes that cover non alpha numeric values
        @@hex_codes = []
        for c in (0..255) do
          if (c >= 0x30 and c <= 0x39) or (c >= 0x41 and c <= 0x5A) or (c >= 0x61 and c <= 0x7A)
            @@hex_codes[c] = nil
          else
            @@hex_codes[c] = c.to_s(16)
          end
        end
=begin
  Encode(immune,input)
  immune is expecting an array of safe characters which are immune form encoding
  input is the data to encode.
=end
        def encode(immune, input)
          if input.instance_of?(Fixnum)
            return encode_char(immune,input)
          end
          encoded_string = ''
          input.chars do |c|
            encoded_string << encode_char(immune,c)
          end
          return encoded_string
        end

        def encode_char(immune, input)
          return input
        end

        def hex_value(c)
          if c.nil?
            return nil
          end

          if c.instance_of?(Fixnum)
            return c.to_s(16)
          end

          if c.getbyte(0) < 0xff
            @@hex_codes[c.getbyte(0)]
          else
            c.getbyte(0).to_s(16)
          end
        end

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
          return decoded_string
        end

        def decode_char(input)
          return input
        end
      end
    end
  end
end