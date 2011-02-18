#
# This code is a direct port of the OWASP ESAPI API
#
# Original Author: Jeff Williams
# Port Author: Sal ScottoDiLuzio
#

module Owasp
  module Esapi
    module Codec
      class CssCodec < BaseCodec
        def encode_char(immune, input)
          if immune.include?(input)
            return input
          end
          hex = hex_value(input)
          unless hex.nil? or hex.empty?
            return "\\#{hex}"
          end
          return input
        end

        def decode_char(input)

          input.mark
          first = input.next
          if first.nil? or !first.eql?('\\')
            input.reset
            return nil
          end
          second = input.next
          if second.nil?
            input.reset
            return nil
          end

          # CSS rules
          # http://www.w3.org/TR/CSS21/syndata.html#characters
          #
          fallthrough = false
          if second == "\r"
            if input.peek?("\n")
              input.next
              fallthrough = true
            end
          end
          if second == "\n" || second == "\f" || second == "\u0000" || fallthrough
            return decode_char(input)
          end

          if !input.is_hex(second)
            return second
          end
          tmp = second
          for i in 1..5 do
            c = input.next
            if c.nil? or c =~ /\s/
              break
            end
            if input.is_hex(c)
              tmp << c
            else
              input.push(c)
            end
          end
          begin
            i = tmp.hex
            if i >= 0x000 and i <= 0x10fff
              return i.chr
            end
          rescue Exception => e
            raise "IllegalState #{e}"
          end
        end
      end
    end
  end
end