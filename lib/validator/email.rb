module Owasp
  module Esapi
    module Validator
      class Email
        
        # In order to make a strong validation for email addresses, it might be a good idea to 
        # make a check for the domain tld.
        # This is a very optional and beta feature, so it is turned off by default.
        attr_reader :validate_tld
        attr_reader :matcher
        
        def initialize(options=nil)
          validate_tld = false
          @matcher = "^(\\w)+[@](\\w)+[.]\\w{3}$"
          unless options.nil? 
            if options.has_key? "validate_tld"
              validate_tld = options["validate_tld"]
            end
          end
        end
        
        def validate(email)
          r = Regexp.new(@matcher)
          ! (email =~ r).nil?
        end
      end
    end
  end
end