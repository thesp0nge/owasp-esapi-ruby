require 'validator/generic_validator'

module Owasp
  module Esapi
    module Validator
      class Email < GenericValidator
        
        EMAIL_REGEX = "^(\\w)+[@](\\w)+[.]\\w{3}$"
        # In order to make a strong validation for email addresses, it might be a good idea to 
        # make a check for the domain tld.
        # This is a very optional and beta feature, so it is turned off by default.
        attr_reader :validate_tld
        
        def initialize(options=nil)
          validate_tld = false
          @matcher = EMAIL_REGEX
          super(@matcher)
          
          unless options.nil? 
            if options.has_key? "validate_tld"
              validate_tld = options["validate_tld"]
            end
          end
        end
      
      end
    end
  end
end