# Implementation of the Codec interface for percent encoding (aka URL encoding).
module Owasp
  module Esapi
    module Codec
      class PercentCodec < BaseCodec

        #  Encode a character for URLs
        def encode_char(immune,input)
          return input if input =~ /[a-zA-Z0-9_.-]/
          # RFC compliance
          return "+" if input == " "
          val = ''
          input.each_byte do |b|
            val << '%' << b.ord.to_h.upcase
          end
          val
        end

        # Formats all are legal both upper/lower case:
        # %hh;
        def decode_char(input)
          input.mark
          first = input.next
          if first.nil?
            input.reset
            return nil
          end
          # check if this is an encoded character
          if first != '%'
            input.reset
            return nil
          end
          # search for 2 hex digits
          tmp = ''
          for i in 0..1 do
            c = input.next_hex
            tmp << c unless c.nil?
          end
          # we found 2, convert to a number
          if tmp.size == 2
            i = tmp.hex
            begin
              return i.chr(Encoding::UTF_8) if i >= START_CODE_POINT and i <= END_CODE_POINT
            rescue Exception => e
            end
          end
          input.reset
          nil
        end
      end
    end
  end
end
