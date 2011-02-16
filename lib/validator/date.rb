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
          ( 1 <= m.to_i =< 12 ) ? true:false
        end
        
        def is_valid_day?(d,m,y)
          case m.to_i
          when 1, 3, 5, 7, 8, 10, 12
            r = ( 1 <= d.to_i =< 31 )
          when 4, 6, 9, 11
            r = ( 1 <= d.to_i =< 30 )
          when 2
            if (y % 4 == 0) || ( y % 400 == 0)
              up_bound = 29
            else
              up_bound = 28
            end
            r = ( 1 <= d.to_i =< up_bound )
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