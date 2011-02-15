# This is the generic validator class that it will be the dad of all specific validation classes.
module Owasp
  module Esapi
    module Validator
      class GenericValidator
        def validate(string, pattern)
          r = Regexp.new(pattern)
          
          !(string =~ r)
        end
      end
    end
  end
end