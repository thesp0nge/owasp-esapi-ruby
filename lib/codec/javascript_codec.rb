module Owasp
  module Esapi
    module Codec
      class JavascriptCodec < BaseCodec

        # Returns backslash encoded numeric format. Does not use backslash character escapes
        # such as, \" or \' as these may cause parsing problems. For example, if a javascript
        # attribute, such as onmouseover, contains a \" that will close the entire attribute and
        # allow an attacker to inject another script attribute.
        def encode_char(immune,input)
          return input if immune.include?(input)
          return input if hex(input).nil?
          temp = hex(input)
          if temp.hex < 256
            return "\\x#{'00'[temp.size,2-temp.size]}#{temp.upcase}"
          end
          "\\u#{'0000'[temp.size,4-temp.size]}#{temp.upcase}"
        end

        # Returns the decoded version of the character starting at index, or
        # null if no decoding is possible.
        # See http://www.planetpdf.com/codecuts/pdfs/tutorial/jsspec.*pdf*
        # Formats all are legal both upper/lower case:
        # *  \\a - special characters
        # *  \\xHH
        # *  \\uHHHH
        # *  \\OOO (1, 2, or 3 digits)
        def decode_char(input)

          input.mark
          first = input.next
          if first.nil?
            input.reset
            return nil
          end
          # check to see if we are dealing with an encoded char
          if first!= "\\"
            input.reset
            return nil
          end
          second = input.next
          if second.nil?
            input.reset
            return nil
          end

          #Check octal codes
          return 0x08.chr if second == "b"
          return 0x09.chr if second == "t"
          return 0x0a.chr if second == "n"
          return 0x0b.chr if second == "v"
          return 0x0c.chr if second == "f"
          return 0x0d.chr if second == "r"
          return 0x22.chr if second == "\""
          return 0x27.chr if second == "\'"
          return 0x5c.chr if second == "\\"
          if second.downcase == "x" # Hex encoded value
            temp = ''
            for i in 0..1 do
              c = input.next_hex
              temp << c unless c.nil?
              if c.nil?
                input.reset
                return nil
              end
            end
            i = temp.hex
            begin
              return i.chr(Encoding::UTF_8) if i >= START_CODE_POINT and i <= END_CODE_POINT
            rescue Exception => e
              input.reset
              return nil
            end
          elsif second.downcase == "u" # Unicode encoded value
            temp = ''
            for i in 0..3 do
              c = input.next_hex
              temp << c unless c.nil?
              if c.nil?
                input.reset
                return nil
              end
            end
            i = temp.hex
            begin
              return i.chr(Encoding::UTF_8) if i >= START_CODE_POINT and i <= END_CODE_POINT
            rescue Exception => e
              input.reset
              return nil
            end
          elsif input.octal?(second) # Octal encoded value
            temp = second
            c = input.next
            unless input.octal?(c)
              input.push(c)
            else
              temp << c
              c = input.next
              unless input.octal?(c)
                input.push(c)
              else
                temp << c
              end
            end
            # build a number
            i = temp.to_i(8)
            begin
              return i.chr(Encoding::UTF_8) if i >= START_CODE_POINT and i <= END_CODE_POINT
            rescue Exception => e
              input.reset
              return nil
            end
          end
          second
        end
      end
    end
  end
end