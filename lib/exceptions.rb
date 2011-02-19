module Owasp
  module Esapi
    class IntrustionException < Exception
      attr_reader :log_message
      def initialize(user_message,log_message)
        super(user_message)
        @log_message = log_message
      end
    end
  end
end