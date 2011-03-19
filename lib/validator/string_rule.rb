require 'stringio'

module Owasp
  module Esapi
    module Validator

      # A validator performs syntax and possibly semantic validation of a single
      # piece of string data from an untrusted source.
      class StringRule < BaseRule
        attr_writer :min,:max,:canonicalize

        # Create an instance of the String vlidator
        # whitelist_pattern is an optionla white listing regex
        def initialize(type,encoder = nil,whitelist_pattern = nil)
          super(type,encoder)
          @white_list = []
          @black_list = []
          @white_list << whitelist_pattern unless whitelist_pattern.nil?
          @min = 0
          @max = 0
          @canonicalize = false
        end

        # Add a whitelist regex
        def add_whitelist(p)
          raise ArgumentError.new("Nil Pattern") if p.nil?
          @white_list << create_regex(p)
        end

        # Add a blacklist regex
        def add_blacklist(p)
          raise ArgumentError.new("Nil Pattern") if p.nil?
          @black_list << create_regex(p)
        end

        # Ensure we dont show the warnings to stderr, just fail the regexp
        def create_regex(p) #:nodoc:
          output = StringIO.open('','w')
          $stderr = output
          begin
            r = /#{p}/ui
          ensure
            output.close
            $stderr = STDERR
          end
        end

        # Checks input against whitelists.
        def check_white_list(context,input,original = nil)
          original = input.dup if original.nil?
          @white_list.each do |p|
            match = p.match(input)
            if match.nil? or not match[0].eql?(input)
              # format user msg
              user = "#{context}: Invalid input. Conform to #{p.to_s}"
              user << " with a max length of #{@max}" unless @max == 0
              # format log message
              log = "Invalid input: context=#{context}, type=#{@name}, pattern=#{p.to_s}"
              log << ", input=#{input}, original=#{original}"
              # raise an error
              raise Owasp::Esapi::ValidationException.new(user,log,context)
            end
          end
          input
        end

        # Checks input against blacklists.
        def check_black_list(context,input,original = nil)
          original = input.dup if original.nil?
          @black_list.each do |p|
            if p.match(input)
              # format user msg
              user = "#{context}: Invalid input. Dangerous input matching #{p.to_s}"
              # format log message
              log = "Dangerous input: context=#{context}, type=#{@name}, pattern=#{p.to_s}"
              log << ", input=#{input}, original=#{original}"
              # raise an error
              raise Owasp::Esapi::ValidationException.new(user,log,context)
            end
          end
          input
        end

        # Checks input lengths
        def check_length(context,input,original = nil)
          original = input.dup if original.nil?
          # check min value
          if input.size < @min
            user = "#{context}: Invalid input, The min length is #{@min} characters"
            log = "Input didnt meet #{@min} chars by #{input.size}: context=#{context}, type=#{@name}, pattern=#{p.to_s}"
            log << ", input=#{input}, original=#{original}"
            raise Owasp::Esapi::ValidationException.new(user,log,context)
          end
          # check max value
          if input.size > @max and @max > 0
            user = "#{context}: Invalid input, The max length is #{@max} characters"
            log = "Input exceed #{@max} chars by #{input.size}: context=#{context}, type=#{@name}, pattern=#{p.to_s}"
            log << ", input=#{input}, original=#{original}"
            raise Owasp::Esapi::ValidationException.new(user,log,context)
          end
          input
        end

        def check_empty(context,input,orig = nil)
          return nil if @allow_nil and input.nil?
          unless input.nil?
            original = input.dup if original.nil?
            return input unless input.empty?
          end
          user = "#{context}: Input required."
          log = "Input required: context=#{context}, type=#{@name}, pattern=#{p.to_s}"
          log << ", input=#{input}, original=#{original}"
          raise Owasp::Esapi::ValidationException.new(user,log,context)
        end

        # Remvoe any non alpha numerics form the string
        def sanitize(context,input)
          whitelist(input,Owasp::Esapi::Ecnoder::CHAR_ALPHANUMERIC)
        end

        # Parse the input, raise exceptions if validation fails
        # see BaseRule
        def valid(context,input)

          data = nil
          return nil if check_empty(context,input).nil?
          # check for pre-canonicalize if we are in sanitize mode
          check_length(context,input) if @canonicalize
          check_white_list(context,input) if @canonicalize
          check_black_list(context,input) if @canonicalize
          if @canonicalize
            data = encoder.canonicalize(input)
          else
            data = input
          end
          # no check again after we figured otu canonicalization
          return nil if check_empty(context,input).nil?
          check_length(context,input)
          check_white_list(context,input)
          check_black_list(context,input)
          data
        end
      end
    end
  end
end
