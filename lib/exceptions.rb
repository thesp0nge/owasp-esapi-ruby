# Various exception used by Esapi
module Owasp
  module Esapi

    # Base Exception class for SecurityExceptions
    class EnterpriseSecurityException < Exception
      attr_reader :log_message
      def initialize(user_msg, log_msg)
        super(user_msg)
        @log_message = log_msg
      end
    end

    # Exception throw if there is an error during Executor processing
    class ExecutorException < EnterpriseSecurityException
    end

    # Intrustion detection exception to be logged
    class IntrustionException < Exception
      attr_reader :log_message
      def initialize(user_message,log_message)
        super(user_message)
        @log_message = log_message
      end
    end

    # ValidatorException used in the rule sets
    class ValidationException < EnterpriseSecurityException
      attr_reader :context
      def initialize(user_msg,log_msg,context)
        super(user_msg,log_msg)
        @context = context
      end
    end

    # Configuration exception
    class ConfigurationException < Exception
      attr_reader :cause
      def initialize(msg,error)
        super(msg)
        @cause = error
      end
    end

  end
end
