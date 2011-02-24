=begin
  VB Script codec
=end
module Owasp
  module Esapi
    module Codec
      class VbScriptCodec < BaseCodec



        def encode_char(immune,input)
          return input if immune.include?(input)
          hex = hex(input)
          return input if hex.nil?
          return "chrw(#{input.ord})"
        end

        def decode_char(input)
          input.mark();
          first = input.next
          if first.nil?
            input.reset
            return nil;
          end
          # if this is not an encoded character, return null
          if first != "\""
            input.reset
            return nil
          end
          input.next
        end
      end
    end
  end
end