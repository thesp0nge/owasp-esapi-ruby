module Owasp
  module Esapi
    module Validator
      # List of Validation exceptions
      # this list is indexed by the context
      class ValidatorErrorList

        # Create a new list
        def initialize()
          @errors = {}
        end

        # Add an error to the list. We will raise ArgumentException if any of the following is true:
        # 1. error is nil
        # 2. context is nil
        # 3. we already have an error for the given context
        # 4. the error isnt a ValidationException
        def <<(error)
          raise ArgumentError.new("Invalid Error") if error.nil?
          if error.instance_of?(ValidationException)
            context = error.context
            raise ArgumentError.new("Invalid context") if context.nil?
            raise ArgumentError.new("Duplicate error") if @errors.has_key?(context)
            @errors[context] = error
          else
            raise ArgumentError.new("Exception was not a ValdiaitonException")
          end
        end

        # Return true if this list is empty
        def empty?
          @errors.empty?
        end

        # Return the size of the list
        def size
          @errors.size
        end

        # Return the array of errors in this list
        def errors
          @errors.values
        end

      end
    end
  end
end
