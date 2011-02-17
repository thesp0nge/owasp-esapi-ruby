# This is the generic validator class that it will be the dad of all specific validation classes.
module Owasp
  module Esapi
    module Validator
      class GenericValidator
        
        attr_accessor :matcher
        
        # Creates a new generic validator.
        # @param [String] matcher the regular expression to be matched from this validator
        def initialize(matcher)
          @matcher = matcher
        end
        
        # Validate a string against the matcher
        # @param [String] string the string that need to be validated
        # @return [Boolean] true if the string matches the regular expression, false otherwise
        def valid?(string)
          r = Regexp.new(@matcher)
          
          !(string =~ r).nil?
        end
      end
    end
  end
end