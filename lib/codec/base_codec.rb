# The Codec interface defines a set of methods for encoding and decoding application level encoding schemes,
# * such as HTML entity encoding and percent encoding (aka URL encoding). Codecs are used in output encoding
# * and canonicalization.  The design of these codecs allows for character-by-character decoding, which is
# * necessary to detect double-encoding and the use of multiple encoding schemes, both of which are techniques
# * used by attackers to bypass validation and bury encoded attacks in data.

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
    # The Codec module, houses Codec implementations
    module Codec
      class BaseCodec
        # start range of valid code points
        START_CODE_POINT = 0x000
        # ending range of valid code points
        END_CODE_POINT = 0x10fff

        @@hex_codes = [] #:nodoc:
        for c in (0..255) do
          if (c >= 0x30 and c <= 0x39) or (c >= 0x41 and c <= 0x5A) or (c >= 0x61 and c <= 0x7A)
            @@hex_codes[c] = nil
          else
            @@hex_codes[c] = c.to_h
          end
        end

        # Encode a String so that it can be safely used in a specific context.
        # immune is an arry or string that contains character tobe ignore
        def encode(immune, input)
          return nil if input.nil?
          encoded_string = ''
          encoded_string.encode!(Encoding::UTF_8)
          input.encode(Encoding::UTF_8).chars do |c|
            encoded_string << encode_char(immune,c)
          end
          encoded_string
        end

        # Default implementation that should be overridden in specific codecs.
        def encode_char(immune, input)
          input
        end

        #  Helper method for codecs to get the hex value of a character
        def hex(c)
          return nil if c.nil?
          b = c[0].ord
          if b < 0xff
            @@hex_codes[b]
          else
            b.to_h
          end
        end

        # Decode a String that was encoded using the encode method in this Class
        def decode(input)
          decoded_string = ''
          seekable = PushableString.new(input.dup)
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

        # Returns the decoded version of the next character from the input string and advances the
        # current character in the PushableString.  If the current character is not encoded, this
        # method MUST reset the PushableString.
        def decode_char(input)
          input
        end

        # Basic min method
        def min(a,b) #:nodoc:
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
