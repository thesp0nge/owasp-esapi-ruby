=begin
  Codec to provide for Oracle string support
  see http://oraqa.com/2006/03/20/how-to-escape-single-quotes-in-strings for details
  This will only prevent SQLinjection in the case of user data being placed within an
  Oracle quoted string such as select * from table where field = ' USERDATA '
=end
module Owasp
  module Esapi
    module Codec
      class OracleCodec < BaseCodec

=begin
  encode ' to ''
=end
        def encode_char(immune,input)
          return "\'\'" if input == "\'"
          input
        end
=begin
  decode '' as '
=end
        def decode_char(input)
          # check first char
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