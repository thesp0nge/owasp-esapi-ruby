#
# Codec to provide for Oracle string support
# see http://oraqa.com/2006/03/20/how-to-escape-single-quotes-in-strings for details
# This will only prevent SQLinjection in the case of user data being placed within an
# Oracle quoted string such as select * from table where field = ' USERDATA '
module Owasp
  module Esapi
    module Codec
      class OracleCodec < BaseCodec

        #  Encodes ' to ''
        def encode_char(immune,input)
          return "\'\'" if input == "\'"
          input
        end

         # Returns the decoded version of the character starting at index, or
         # nil if no decoding is possible.
         #
         #  Formats all are legal
         #   '' decodes to '
         def decode_char(input)
          # check first *char*
          input.mark
          first = input.next
          if first.nil?
            input.reset
            return nil
          end
          # if it isnt an encoded string return nil
          unless first == "\'"
            input.reset
            return nil
          end
          # if second isnt an encoded marker return nil
          second = input.next
          unless second == "\'"
            input.reset
            return nil
          end
          return "\'"
        end
      end
    end
  end
end