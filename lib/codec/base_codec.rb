#
# This code is a direct port of the OWASP ESAPI API
#
# Original Author: Jeff Williams
# Port Author: Sal ScottoDiLuzio
#
# monkey patch 1.8 so we can run in 1.8 or 1.9 ruby

if RUBY_VERSION.to_f < 1.9
$KCODE='u'
  class String
    def getbyte(index)
      return self[index]
    end
  end
end


module Owasp
  module Esapi
    module Codec
      class BaseCodec
        @@hex_codes = []
        for c in (0..255) do
          if (c >= 0x30 and c <= 0x39) or (c >= 0x41 and c <= 0x5A) or (c >= 0x61 and c <= 0x7A)
            @@hex_codes[c] = nil
          else
            @@hex_codes[c] = c.to_s(16)
          end
        end

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