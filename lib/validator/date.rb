require 'validator/generic_validator'

module Owasp
  module Esapi
    module Validator
      class Date < GenericValidator
        
        US_FORMAT_NUMERIC = "^\\d{2}[/-]\\d{2}[/-]\\d{4}$"
        US_FORMAT_STRING_SHORT = "^\\w{3} \\d{2}[,][ ]\\d{4}"
        US_FORMAT_STRING_LONG = "^\\w+ \\d{2}[,][ ]\\d{4}"
        
        EU_FORMAT_NUMERIC = US_FORMAT_NUMERIC
        
        attr_accessor :eu_format
        
        def initialize(options=nil)
          @matcher = ""
          # Since regexp for european and us short date pattern is the same, only month and day have 
          # to be exchanged, I have to introduce this flag. In a further refactoring we can get rid of it
          @eu_format = false
          super(@matcher)
        end
        
        def valid?(date)
          unless ! super(date)
            if @matcher == US_FORMAT_NUMERIC && ! @eu_format
              s = date.split('/')
              # the s lenght is 3 due to regular expression checking.
              # we are also sure that there are no alfa chars in the string but the separator
              # let's see if this a meaningful date.
              return (is_valid_month?(s[0].to_i) && is_valid_day?(s[1].to_i, s[0].to_i, s[2].to_i) && is_valid_year?(s[2].to_i))
            end
            if @matcher == EU_FORMAT_NUMERIC && @eu_format
              s = date.split('/')
              # the s lenght is 3 due to regular expression checking.
              # we are also sure that there are no alfa chars in the string but the separator
              # let's see if this a meaningful date.
              return (is_valid_month?(s[1].to_i) && is_valid_day?(s[0].to_i, s[1].to_i, s[2].to_i) && is_valid_year?(s[2].to_i))
            end
            if @matcher == US_FORMAT_STRING_SHORT || @matcher == US_FORMAT_STRING_LONG
              s = date.gsub(',', '').split(' ')
              # I'm pretty sure about what's inside the array due to regular expression check.
              # s[0] is the month here, written in short alphanumeric form
              # s[1] is the month day digit
              # s[2] is the year
              m_i = month_to_digit(s[0])
              
              return (is_valid_month?(m_i) && is_valid_day?(s[1].to_i, m_i, s[2].to_i) && is_valid_year?(s[2].to_i))
            end
          end
          false
        end
        
        def month_to_digit(m)
          case m.downcase
          when 'jan', 'january'
            r= 1
          when 'feb', 'february'
            r= 2
          when 'mar', 'march'
            r = 3
          when 'apr', 'april'
            r = 4
          when 'may'
            r = 5
          when 'jun', 'june'
            r = 6
          when 'jul', 'july'
            r = 7
          when 'aug', 'august'
            r = 8
          when 'sept', 'september'
            r = 9
          when 'oct', 'october'
            r = 10
          when 'nov', 'november'
            r = 11
          when 'dec', 'december'
            r = 12
          else 
            r = -1
          end
          
          r
        end
       
        def is_valid_month?(m)
          ((m.class == Fixnum) && ( 1<= m ) && (m <= 12)) ? true : false
        end
        
        def is_valid_day?(d,m,y)
          r = false
          case m
          when 1, 3, 5, 7, 8, 10, 12
            if (1 <= d ) && ( d <= 31 )
              r = true
            end
          when 4, 6, 9, 11
            if (1 <= d) && ( d <= 30 )
              r = true
            end
          when 2
            if (y % 4 == 0) || ( y % 400 == 0)
              up_bound = 29
            else
              up_bound = 28
            end
            if (1 <= d) && ( d <= up_bound )
              r = true
            end
          else 
            r = false
          end
          
          r
        end
        
        def is_valid_year?(y)
          (y >=0)
        end
          
      end
    end
  end
end