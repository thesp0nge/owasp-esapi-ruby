module Owasp
  module Esapi
    module Sanitizer
        
      # This is the Cross site scripting sanitizer class.
      # {http://bit.ly/AJVmn The XSS Cheat sheet at Owasp site}
      class Xss
          
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
        # @param [String], tainted. The string needs to be sanitized
        # @return [String] the input string sanitized equivalent 
        def sanitize(tainted)
          untainted = tainted
            
          untainted = rule1_sanitize(tainted)
            
          # Start - RULE #2 - Attribute Escape Before Inserting Untrusted Data into HTML Common Attributes
          # End - RULE #2 - Attribute Escape Before Inserting Untrusted Data into HTML Common Attributes
            
          # Start - RULE #3 - JavaScript Escape Before Inserting Untrusted Data into HTML JavaScript Data Values
          # End - RULE #3 - JavaScript Escape Before Inserting Untrusted Data into HTML JavaScript Data Values
            
          # Start - RULE #4 - CSS Escape Before Inserting Untrusted Data into HTML Style Property Values
          # End - RULE #4 - CSS Escape Before Inserting Untrusted Data into HTML Style Property Values
          
          untainted
        end
        private
          def rule1_sanitize(taint) 
            # Start - RULE #1 - HTML Escape Before Inserting Untrusted Data into HTML Element Content

            # This *must* be the first substitution, otherwise it will substitute also & characters in 
            # valid HTML entities
            untainted = untainted.gsub("&", "&amp;")
            untainted = untainted.gsub("<", "&lt;")
            untainted = untainted.gsub(">", "&gt;")
            untainted = untainted.gsub("\"", "&quot;")
            untainted = untainted.gsub("\'", "&#x27;")
            untainted = untainted.gsub("/", "&#x2F;")

            # End - RULE #1 - HTML Escape Before Inserting Untrusted Data into HTML Element Content
            untainted
          end
      end
    end
  end
end