# This is the generic validator class that it will be the dad of all specific validation classes.
module Owasp
  module Esapi
    module Validator
      class GenericValidator
        
        attr_accessor :matcher
        
        # Creates a new generic validator.
        # @param [String] matcher, the regular expression to be matched from this validator
        def initialize(matcher)
          @matcher = matcher
        end
        
        # Validate a string against the matcher
        def validate(string)
          r = Regexp.new(@matcher)
          
          !(string =~ r).nil?
        end
      end
    end
  end
end