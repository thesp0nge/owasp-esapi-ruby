module Owasp
  module Esapi
    module Ruby
      module Validator
        class Zipcode
          
          
          
          attr_reader :matcher
         
          def initialize(custom_regex = nil)
            
            # Matcher is tuned to match a valid US ZIP CODE, that means either 5 numbers, or 5 numbers, 
            # plus a dash, then 4 more numbers.
            @matcher = "/^\d{5}([\-]\d{4})?$/"
            @matcher = custom_regex unless custom_regex.nil?
          end
          
          def validate(zipcode)
            r = Regexp.new(@matcher)
            puts "SSS " + zipcode.scan(r).to_s + " " +zipcode.scan(r).count.to_s
            ! zipcode.scan(r).count == 0
            
          end
        end
      end
    end
  end
end