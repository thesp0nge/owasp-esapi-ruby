module Owasp
  module Esapi
    class IntrustionDetector

      def add_exception(exception)
        return unless Esapi.security_config.ids?
        if exception.is_a?(EnterpriseSecurityException)
          # log a security failure warning, with th log message and exception
        else
          # log a security failure warning with the exception message
        end

        # Add exception to current user

      end

      def add_event(event,message)
        return unless Esapi.security_config.ids?

      end

    end
    private
    class IntrustionEvent
      def initialize(key)
        @key = key
        @times = []
      end
      def increment(count,interval)
        return unless Esapi.security_config.ids?

        now = Time.now
        @times.unshift(now)
        if @times.size > count
          @times.slice!(count,@times.size - count)
        end
        if @times.size == count
          past = @times.last
          if now - past < (interval * 1000)
            raise IntrustionException.new("Threshold exceeded","Exceeded threshold for #{key}")
          end
        end
      end

    end
  end
end
