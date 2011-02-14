module Owasp
  module Esapi
    module Ruby
      module Validator
        class Zipcode
          
          ITALIAN_ZIPCODE = "\\d\\d\\d\\d\\d"
          
          
          attr_accessor :matcher
         
          def initialize(custom_regex = nil)
            
            # Matcher is tuned to match a valid US ZIP CODE, that means either 5 numbers, or 5 numbers, 
            # plus a dash, then 4 more numbers.
            @matcher = "^\\d\\d\\d\\d\\d([-]\\d\\d\\d\\d)?$"
            @matcher = custom_regex unless custom_regex.nil?
          end
          
          def matcher=(custom_regex) 
            @matcher = custom_regex
          end
          
          def validate(zipcode)
            r = Regexp.new(@matcher)
            
            if zipcode.scan(r).count == 0
              return false
            end
            
             zipcode.scan(r)[0] == zipcode
            
          end
        end
      end
    end
  end
end