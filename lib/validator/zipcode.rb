require 'validator/generic_validator'

module Owasp
  module Esapi
    module Validator
      
      # This is a validator class for zip codes.
      class Zipcode < GenericValidator
      
        ITALIAN_ZIPCODE = "^\\d{5}$"
        US_ZIPCODE = "^\\d{5}(\\-\\d{4})?$"
        
        # Creates a new Zipcode validator.
        # @param custom_regex if you don't find your locale zip code regular expression, you can provide a 
        # very custom one
        def initialize(options = nil)
          # Matcher is tuned to match a valid US ZIP CODE, that means either 5 numbers, or 5 numbers, 
          # plus a dash, then 4 more numbers.
          @matcher = US_ZIPCODE
          @matcher = options["custom_regex"] unless (options.nil? || ! options.has_key?("custom_regex"))
          super(@matcher)
        end
        
      end
    end
  end
end