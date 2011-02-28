require 'date'

# DateTime now has a to_time method injected in
class DateTime
  def to_time
    self.offset == 0 ? ::Time.utc(year, month, day, hour, min, sec) : self
  end
end

module Owasp
  module Esapi
    module Validator

      # A validator performs syntax and possibly semantic validation of a single
      # piece of string data from an untrusted source. This class will return
      # Time objects, as they are more flexible to reformat to for timezones
      # and calendars
      # Format variables, from rdoc
      # %a - The abbreviated weekday name (``Sun'')
      # %A - The  full  weekday  name (``Sunday'')
      # %b - The abbreviated month name (``Jan'')
      # %B - The  full  month  name (``January'')
      # %c - The preferred local date and time representation
      # %d - Day of the month (01..31)
      # %H - Hour of the day, 24-hour clock (00..23)
      # %I - Hour of the day, 12-hour clock (01..12)
      # %j - Day of the year (001..366)
      # %m - Month of the year (01..12)
      # %M - Minute of the hour (00..59)**
      # %p - Meridian indicator (``AM''  or  ``PM'')
      # %S - Second of the minute (00..60)
      # %U - Week  number  of the current year,
      #        starting with the first Sunday as the first
      #        day of the first week (00..53)
      # %W - Week  number  of the current year,
      #        starting with the first Monday as the first
      #        day of the first week (00..53)
      # %w - Day of the week (Sunday is 0, 0..6)
      # %x - Preferred representation for the date alone, no time
      # %X - Preferred representation for the time alone, no date
      # %y - Year without a century (00..99)
      # %Y - Year with century
      # %Z - Time zone name
      # %% - Literal ``%'' character
      class DateValidator < BaseValidator
        attr :format
        # Create a validator, if no format is specificed
        # We assume %b $d, %Y i.e. September 11, 2001
        def initialize(type, encoder = nil, dateformat = nil)
          super(type,encoder)
          @format = dateformat
          @format = "%B %d, %Y" if dateformat.nil?
        end

        # Parse the input, raise exceptions if validation fails
        # Returns a Time object
        # see BaseRule
        def valid(context,input)
          # check for empty
          if input.nil? or input.empty?
            if @allow_nil
              return nil
            end
            user = "#{context}: Input date required"
            log = "Input date required: context=#{context}, input=#{input}"
            raise Owasp::Esapi::ValidationException.new(user,log,context)
          end
          # clean the input
          clean = @encoder.canonicalize(input)
          begin
            return DateTime.strptime(clean,@format).to_time
          rescue ArgumentError => failed
            user="#{context}: Input date required"
            log="Input date required: context=#{context}, input=#{input}"
            raise Owasp::Esapi::ValidationException.new(user,log,context)
          end
        end

        # Calls valid, with any failures causing it to return a zero Time object
        def sanitize(context,input)
          d = Time.new(0)
          begin
            d = valid(context,input)
          rescue ValidationException => e
          end
          return d
        end

      end
    end
  end
end