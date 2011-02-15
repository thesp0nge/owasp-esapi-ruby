require 'validator/generic_validator'

module Owasp
  module Esapi
    module Validator
      class Zipcode < GenericValidator
      
        ITALIAN_ZIPCODE = "^\\d{5}$"
        US_ZIPCODE = "^\\d{5}(\\-\\d{4})?$"
        
        def initialize(custom_regex = nil)
          # Matcher is tuned to match a valid US ZIP CODE, that means either 5 numbers, or 5 numbers, 
          # plus a dash, then 4 more numbers.
          @matcher = US_ZIPCODE
          @matcher = custom_regex unless custom_regex.nil?
          super(@matcher)
        end
        
      end
    end
  end
end