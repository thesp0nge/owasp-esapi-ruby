require 'antisamy'
module Owasp
  module Esapi
    module Validator
      class HTMLRule < BaseRule

        def initialize(type,encoder = nil,whitelist_pattern = nil)
          super(type,encoder)
          @string_rule = StringRule.new(type,encoder,whitelist_pattern)
          @string_rule.canonicalize = true
          begin
            @@policy ||= AntiSamy.policy(Esapi.security_config.resource("antisamy"))
          rescue Exception => e
            puts e
            raise ConfigurationException.new("Failed to load antisamy policy",e)
          end
        end


        def sanitize(context,input)
          safe = ''
          begin
            safe = antisamy(context,input)
          rescue Exception => e
          end
          safe
        end

        def antisamy(context,input)
          if input.nil?
            if @allow_nil
              return nil
            end
            user = "#{context}: Input number required"
            log = "Input number required: context=#{context}, input=#{input}"
            raise Owasp::Esapi::ValidationException.new(user,log,context)
          end
          canonical = @string_rule.valid(context,input)
          begin
            r = AntiSamy.scan(canonical,@@policy)
            unless r.messages.empty?
              Esapi.logger.info(:SECURITY_FAILURE,"Cleaned up HTML error #{r.messages}")
            end
            # AntiSamy will wrap loose content in a <p> if there is no starting tag
            clean = r.clean_html
            # Strip out the >p> tags
            if clean =~ /^\<p\>(.*)\<\/p\>$/
              x  = $1
              unless input =~ /^\</
                clean = x
              end
            end
            return clean.strip
          rescue Exception => e
            user = "#{context}: Invalid HTML input"
            log = "Invalid HTML input: context=#{context} error=#{e}"
            raise Owasp::Esapi::ValidationException.new(user,log,context)
          end
        end

        def valid(context,input)
          antisamy(context,input)
        end

      end
    end
  end
end
