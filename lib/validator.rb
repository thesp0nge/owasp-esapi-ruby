require 'validator/validator_error_list'
require 'validator/base_rule'
require 'validator/string_rule'
require 'validator/date_rule'
require 'validator/integer_rule'
require 'validator/float_rule'
require 'validator/html_rule'

module Owasp
  module Esapi
    module Validator
      # Encoder to use for the validator
      @@encoder ||= Owasp::Esapi.encoder

      def self.encoder=(e)
        raise ArgumentError, "invalid encoder" if e.nil?
        raise ArgumentError unless e.is_a?(Owasp::Esapi::Encoder)
        @@encoder = e
      end

      # Calls validate_input and returns true if no exceptions are thrown.
      def self.valid_string?(context,input,type,max_len,allow_nil, canonicalize = true)
        begin
          validate_string(context,input,type,max_len,allow_nil,true)
          return true
        rescue Exception => e
          return false
        end
      end

      # Returns canonicalized and validated input as a String. Invalid input will generate a descriptive ValidationException,
      # and input that is clearly an attack will generate a descriptive IntrusionException.
      # if the error_list is given, exceptions will be added to the list instead of being thrown
      def self.validate_string(context,input,type,max_len,allow_nil, canonicalize = true, error_list = nil)
        begin
          string_rule = Owasp::Esapi::Validator::StringRule.new(type,@@encoder)
          p = Owasp::Esapi.security_config.pattern(type)
          if p.nil?
            string_rule.add_whitelist(type)
          else
            string_rule.add_whitelist(p)
          end
          string_rule.allow_nil = allow_nil
          string_rule.canonicalize = canonicalize
          string_rule.max = max_len
          return string_rule.valid(context,input)
        rescue ValidationException => e
          if error_list.nil?
            raise e
          else
            error_list << e
          end
        end
        return ""
      end
    end
  end
end
