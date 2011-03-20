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

      #Change the active encoder used by the validator
      def self.encoder=(e)
        raise ArgumentError, "invalid encoder" if e.nil?
        raise ArgumentError unless e.is_a?(Owasp::Esapi::Encoder)
        @@encoder = e
      end

      # Calls validate_input and returns true if no exceptions are thrown.
      def self.valid_string?(context,input,type,max_len,allow_nil, canonicalize = true)
        begin
          valid_string(context,input,type,max_len,allow_nil,true)
          return true
        rescue Exception => e
          return false
        end
      end

      # Returns canonicalized and validated input as a String. Invalid input will generate a descriptive ValidationException,
      # and input that is clearly an attack will generate a descriptive IntrusionException.
      # if the error_list is given, exceptions will be added to the list instead of being thrown
      def self.valid_string(context,input,type,max_len,allow_nil, canonicalize = true, error_list = nil)
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


      # Calls valid_date and returns true if no exceptions are thrown.
      def self.valid_date?(context,input, format, allow_nil)
        begin
          valid_date(context,input,format,allow_nil)
          return true
        rescue Exception => e
          return false
        end
      end

      # Returns a valid date as a Date. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
      # will generate a descriptive IntrusionException.
      # if the error_list is given, exceptions will be added to the list instead of being thrown
      def self.valid_date(context, input, format, allow_nil, error_list = nil)
        begin
          date_rule = DateRule.new("SimpleDate",@@encoder,format)
          date_rule.allow_nil = allow_nil
          date_rule.valid(context,input)
        rescue ValidationException => e
          if error_list.nil?
            raise e
          else
            error_list << e
          end
        end
        return nil
      end

      # Calls valid_html and returns true if no exceptions are thrown.
      def self.valid_html?(context, input, max_len, allow_nil)
        begin
          valid_html(context,input,max_len,allow_nil)
          return true
        rescue Exception => e
          return false
        end
      end

      # Returns canonicalized and validated "safe" HTML that does not contain unwanted scripts in the body, attributes, CSS, URLs, or anywhere else.
      # Implementors should reference the OWASP AntiSamy project for ideas
      # on how to do HTML validation in a whitelist way, as this is an extremely difficult problem.
      # if the error_list is given, exceptions will be added to the list instead of being thrown
      def self.valid_html(context,input,max_len,allow_nil,error_list = nil)
        begin
          html_rule = HTMLRule.new("SafeHTML",@@encoder)
          html_rule.allow_nil = allow_nil
          html_rule.max = max_len
          html_rule.canonicalize = false
          return html_rule.valid(context,input)
        rescue ValidationException => e
          if error_list.nil?
            raise e
          else
            error_list << e
          end
        end
        return ""
      end

      # Calls valid_directory and returns true if no exceptions are thrown.
      def self.valid_directory?(context, input, parent, allow_nil)
         begin
            valid_directory(context,input,parent,allow_nil)
            return true
          rescue Exception => e
            return false
          end
      end

      # Returns a canonicalized and validated directory path as a String, provided that the input
      # maps to an existing directory that is an existing subdirectory (at any level) of the specified parent. Invalid input
      # will generate a descriptive ValidationException, and input that is clearly an attack
      # will generate a descriptive IntrusionException.
      # if the error_list is given, exceptions will be added to the list instead of being thrown
      def self.valid_directory(context, input, parent, allow_nil, error_list = nil)
        begin
          # Check for nil
          if input.nil?
            if allow_nil
              return nil
            end
            user = "#{context}: Input directory path required"
            log = "Input directory path required: context=#{context}, input=#{input}"
            raise ValidationException.new(user,log,context)
          end
          cparent = File.expand_path(parent)
          cdir = File.expand_path(input)
          # if the parent a file object?
          raise ValidationException.new("#{context}: Input directory name","Invalid directory, does not exist: context=#{context}, input=#{input}",context) unless File.exists?(cdir)
          raise ValidationException.new("#{context}: Input directory name","Invalid directory, not a directory: context=#{context}, input=#{input}",context) unless Dir.exists?(cdir)
          raise ValidationException.new("#{context}: Input directory name","Invalid directory, parent does not exist: context=#{context}, input=#{input}",context) unless File.exists?(cparent)
          raise ValidationException.new("#{context}: Input directory name","Invalid directory, parent not a directory: context=#{context}, input=#{input}",context) unless Dir.exists?(cparent)
          raise ValidationException.new("#{context}: Input directory name","Invalid directory, not inside specified parent: context=#{context}, input=#{input}",context) unless cdir.index(cparent) == 0
          clean_path = valid_string(context,cdir,"DirectoryName",255,false)
          raise ValidationException.new("#{context}: Input directory name","Invalid directory name does not match the canonical path: context=#{context}, input=#{input}",context) unless clean_path.eql?(input)
          return clean_path
        rescue ValidationException => e
          if error_list.nil?
            raise e
          else
            error_list << e
          end
        end
        return ""
      end

      # Filename
      # Integer
      # Float
      # FileContents
      # Upload
      # ItemList
      # Http Parameters
      # Printable
      # Relocation Path


    end
  end
end
