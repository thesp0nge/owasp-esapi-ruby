# Expand Integer to add Min and Max values
class Integer #:nodoc:
  N_BYTES = [42].pack('i').size
  N_BITS = N_BYTES * 8
  MAX = 2 ** (N_BITS - 2) - 1
  MIN = -MAX - 1
end

module Owasp
  module Esapi
    module Validator

      # A ValidationRule performs syntax and possibly semantic validation of a single
      # piece of data from an untrusted source.
      class BaseRule
        attr_accessor :encoder, :name, :allow_nil
        def initialize(name,encoder=nil)
          @name = name
          @encoder = encoder
          @encoder = Owasp::Esapi.encoder if @encoder.nil?
          @allow_nil = false
        end

        # return true if the input passes validation
        def valid?(context,input)
          valid = false
          begin
            valid(context,input)
            valid = true
          rescue Exception =>e
          end
          valid
        end

        # Parse the input, calling the valid method
        # if an exception if thrown it will be added
        # to the ValidatorErrorList object. This method allows for multiple rules to be executed
        # and collect all the errors that were invoked along the way.
        def validate(context,input, errors=nil)
          valid = nil
          begin
            valid = valid(context,input)
          rescue ValidationException => e
            errors<< e unless errors.nil?
          end
          input
        end

        # Parse the input, raise exceptions if validation fails
        # sub classes need to implment this method as the base class will always raise an
        # exception
        def valid(context,input)
          raise Owasp::Esapi::ValidationException.new(input,input,context)
        end

        # Try to call get *valid*, then call sanitize, finally return a default value
        def safe(context,string)
          valid = nil
          begin
            valid = valid(context,input)
          rescue ValidationException => e
            return sanitize(context,input)
          end
          return valid
        end

        # The method is similar to getSafe except that it returns a
        # harmless object that <b>may or may not have any similarity to the original
        # input (in some cases you may not care)</b>. In most cases this should be the
        # same as the getSafe method only instead of throwing an exception, return
        # some default value. Subclasses should implment this method
        def sanitize(context,input)
          input
        end

        # Removes characters that aren't in the whitelist from the input String.
        # chars is expected to be string
        def whitelist(input,list)
          rc = ''
          input.chars do |c|
            rc << c if list.include?(c)
          end
          rc
        end

      end

    end
  end
end
