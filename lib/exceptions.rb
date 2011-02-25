module Owasp
  module Esapi
    # Exception throw if ther eis an error during Executor processing
    class ExecutorException < Exception
      def initialize(msg)
        super(msg)
      end
    end
    # Intrustion detection exception to be logged
    class IntrustionException < Exception
      attr :log_message
      def initialize(user_message,log_message)
        super(user_message)
        @log_message = log_message
      end
    end
  end
end