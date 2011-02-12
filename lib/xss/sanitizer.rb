module Owasp
  module Esapi
    module Ruby
      module Xss
        class Sanitizer
          
          attr_accessor :smart
          # Creates a new sanitizer
          # @param [Boolean], smart.
          #     A boolean that says if sanitizer can blindly escape all 'dangerous' characters 
          #     in their html entity or rather if it should try to guess if the string needs 
          #     sanitizing is a xss attack vector or not and then let the string to pass by.
          def initialize(smart=false)
            self.smart= smart
          end
          
          # Todo, we should really investigate if dangerous chars have to be trimmed or substituted.
          # I'm (Paolo) choosing substitute right now... we'll change it later.
          def sanitize(string)
            string.gsub("<", "&lt;")
          end
        end
      end
    end
  end
end