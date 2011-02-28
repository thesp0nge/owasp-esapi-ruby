# Implementation of the Codec interface for 'quote' encoding from VBScript.
module Owasp
  module Esapi
    module Codec
      class VbScriptCodec < BaseCodec

        # Encode a String so that it can be safely used in a specific context.
        def encode(immune, input)
          encoded_string = ''
          encoding = false
          inquotes = false
          encoded_string.encode!(Encoding::UTF_8)
          i = 0
          input.encode(Encoding::UTF_8).chars do |c|
            if Owasp::Esapi::Encoder::CHAR_ALPHANUMERIC.include?(c) or immune.include?(c)
              encoded_string << "&" if encoding and i > 0
              encoded_string << "\"" if !inquotes and i > 0
              encoded_string << c
              inquotes = true
              encoding = false
            else
              encoded_string << "\"" if inquotes and i < input.size
              encoded_string << "&" if i > 0
              encoded_string << encode_char(immune,c)
              inquotes = false
              encoding = true
            end
            i += 1
          end
          encoded_string
        end
        # Returns quote-encoded character
        def encode_char(immune,input)
          return input if immune.include?(input)
          hex = hex(input)
          return input if hex.nil?
          return "chrw(#{input.ord})"
        end

        # Returns the decoded version of the character starting at index, or
        # nil if no decoding is possible.
        #
        # Formats all are legal both upper/lower case:
        # "x - all special characters
        # " + chr(x) + "  - not supported

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
