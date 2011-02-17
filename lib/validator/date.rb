require 'validator/generic_validator'

module Owasp
  module Esapi
    module Validator
      class Date < GenericValidator
        
        US_FORMAT_NUMERIC = "^\\d{2}[/-]\\d{2}[/-]\\d{4}$"
        
        def initialize(options=nil)
          @matcher = ""
          super(@matcher)
        end
        
        def valid?(date)
          unless ! super(date)
            s = date.split('/')
            # the s lenght is 3 due to regular expression checking.
            # we are also sure that there are no alfa chars in the string but the separator
            # let's see if this a meaningful date.
            
          end
          false
        end
        
       
        def is_valid_month?(m)
          if ( 1<= m.to_i) && (m.to_i <= 12)
            true
          else
            false
          end
        end
        
        def is_valid_day?(d,m,y)
          r = false
          case m.to_i
          when 1, 3, 5, 7, 8, 10, 12
            if (1 <= d.to_i) && ( d.to_i <= 31 )
              r = true
            end
          when 4, 6, 9, 11
            if (1 <= d.to_i) && ( d.to_i <= 30 )
              r = true
            end
          when 2
            if (y % 4 == 0) || ( y % 400 == 0)
              up_bound = 29
            else
              up_bound = 28
            end
            if (1 <= d.to_i) && ( d.to_i <= up_bound )
              r = true
            end
          else 
            r = false
          end
          
          r
        end
        
        def is_valid_year?(y)
          (y>=0)
        end
          
      end
    end
  end
end