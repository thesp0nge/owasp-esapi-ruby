module Owasp
  module Esapi
    module Validator
      class FloatValidator < BaseValidator
        attr_accessor :min, :max

        def initialize(type,encoder=nil,min=nil,max=nil)
          super(type,encoder)
          @min = min
          @max = max
          @min = Float::MIN if min.nil?
          @max = Float::MAX if max.nil?
        end

        # Validate the input context as an integer
        def valid(context,input)
          if input.nil?
            if @allow_nil
              return nil
            end
            puts "::#{input}::"
            user = "#{context}: Input number required"
            log = "Input number required: context=#{context}, input=#{input}"
            raise Owasp::Esapi::ValidationException.new(user,log,context)
          end
          clean = @encoder.canonicalize(input)
          if @min > @max
            user = "#{context}: Invalid number input: context"
            log = "Validation parameter error for number: maxValue ( #{max}) must be greater than minValue ( #{min}) for #{context}"
            raise Owasp::Esapi::ValidationException.new(user,log,context)
          end
          begin
            user = "Invalid number input must be between #{min} and #{max}: context=#{context}"
            log = "Invalid number input must be between #{min} and #{max}: context=#{context}, input=#{input}"
            i = Float(clean)
            #check min
            if i < @min
              raise Owasp::Esapi::ValidationException.new(user,log,context)
            end
            # check max
            if i > @max
              raise Owasp::Esapi::ValidationException.new(user,log,context)
            end
            # check infinity
            if i.infinite?
              user = "#{context}: Invalid number input: context"
              log = "Invalid double input is infinite context=#{context} input=#{input}"
              raise Owasp::Esapi::ValidationException.new(user,log,context)
            end
            # checknan
            if i.nan?
              user = "#{context}: Invalid number input: context"
              log = "Invalid double input not a number context=#{context} input=#{input}"
              raise Owasp::Esapi::ValidationException.new(user,log,context)
            end
            return i
          rescue Exception => e
            puts e
            user = "#{context}: Input number required"
            log = "Input number required: context=#{context}, input=#{input}"
            raise Owasp::Esapi::ValidationException.new(user,log,context)
          end
        end

        # This will call valid and return a 0 if its invalid
        def sanitize(context,input)
          result = 0
          begin
            result= valid(context,input)
          rescue ValidationException => e
          end
          result
        end
      end
    end
  end
end
