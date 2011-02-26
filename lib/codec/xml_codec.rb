# Implementation of the Codec interface for XML entity encoding.
# This differes from HTML entity encoding in that only the following
# named entities are predefined:
# * lt
# * gt
# * amp
# * apos
# * quot
#
# However, the XML Specification 1.0 states in section 4.6 "Predefined
# Entities" that these should still be declared for interoperability
# purposes. As such, encoding in this class will not use them.
#
# It's also worth noting that unlike the HTMLEntityCodec, a trailing
# semicolon is required and all valid codepoints are accepted.
#
# Note that it is a REALLY bad idea to use this for decoding as an XML
# document can declare arbitrary entities that this Codec has no way
# of knowing about. Decoding is included for completeness but it's use
# is not recommended. Use a XML parser instead!

module Owasp
  module Esapi
    module Codec
      class XmlCodec < BaseCodec

        def initialize
          @longest_key = 0
          @lookup_map = {}
          ENTITY_MAP.each_key do |k|
            if k.size > @longest_key
              @longest_key += 1
            end
            @lookup_map[k.downcase] = k
          end
        end

        # Encodes a Character using XML entities as necessary.
        def encode_char(immune,input)
          return input if immune.include?(input)
          return input if input =~ /[a-zA-Z0-9\\t ]/
          return "&#x#{hex(input)};"
        end

        # Returns the decoded version of the character starting at index, or
        # nil if no decoding is possible.
        def decode_char(input)
          input.mark
          result = nil
          # check first
          first = input.next
          return nil if first.nil?
          return first unless first == "&"
          # check second
          second = input.next
          if second == "#"
            result = numeric_entity(input)
          elsif second =~ /[a-zA-Z]/
            input.push(second)
            result = named_entity(input)
          else
            input.push(second)
            return nil
          end

          if result.nil?
            input.reset
          end
          result
        end

        def numeric_entity(input) #:nodoc:
          first = input.peek
          return nil if first.nil?
          if first.downcase.eql?("x")
            input.next
            return parse_hex(input)
          end
          return parse_number(input)
        end

        #  parse the hex value back to its decimal value
        def parse_hex(input) #:nodoc:
          result = ''
          while input.next?
            c = input.peek
            if "0123456789ABCDEFabcdef".include?(c)
              result << c
              input.next
            elsif c == ";"
              input.next
              break
            else
              return nil
            end
          end
          begin
            i = result.hex
            return i.chr(Encoding::UTF_8) if i >= START_CODE_POINT and i <= END_CODE_POINT
          rescue Exception => e
          end
          nil
        end

        #  parse a number out of the encoded value
        def parse_number(input) #:nodoc:
          result = ''
          missing_semi = true
          while input.next?
            c = input.peek
            if c =~ /\d/
              result << c
              input.next
            elsif c == ';'
              input.next
              break;
            elsif not c =~ /\d/
              return nil
            else
              break;
            end
          end

          begin
            i = result.to_i
            return i.chr(Encoding::UTF_8) if i >= START_CODE_POINT and i <= END_CODE_POINT
          rescue Exception => e
          end
          nil
        end

        #  extract the named entity fromt he input
        # we convert the entity to the real character i.e. &amp; becoems &
        def named_entity(input) #:nodoc:
          possible = ''
          len = min(input.remainder.size,@longest_key+1)
          found_key = false
          last_possible = ''
          for i in 0..len do
            possible << input.next if input.next?
            # we have to find the longest match
            # so we dont find sub values
            if @lookup_map[possible.downcase]
              last_possible = @lookup_map[possible.downcase]
            end
          end
          # no matches found return
          return nil if last_possible.empty?
          return nil unless possible.include?(";")
          # reset the input and plow through
          input.reset
          for i in 0..last_possible.size
            input.next if input.next?
          end
          possible = ENTITY_MAP[last_possible]
          input.next # consume the ;
          return possible unless possible.empty?
          return nil
        end

        # Entity maps
        ENTITY_MAP = {
          "lt" => "<",
          "gt" => ">",
          "amp" => "&",
          "apos" => "\'",
          "quot" => "\""
        }

      end
    end
  end
end
