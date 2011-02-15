module Owasp
  module Esapi
    module Validator
      class Zipcode
      
        ITALIAN_ZIPCODE = "\\d{5}"
      
      
        attr_accessor :matcher
     
        def initialize(custom_regex = nil)
        
          # Matcher is tuned to match a valid US ZIP CODE, that means either 5 numbers, or 5 numbers, 
          # plus a dash, then 4 more numbers.
          @matcher = "^\\d{5}(\\-\\d{4})?$"
          @matcher = custom_regex unless custom_regex.nil?
        end
      
      
        def validate(zipcode)
          r = Regexp.new(@matcher)
        
          # (zipcode =~ r) == 0
          !(zipcode =~ r).nil?
        end
      end
    end
  end
end