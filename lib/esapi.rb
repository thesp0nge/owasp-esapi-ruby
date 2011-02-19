# STUB code, this should be replaced by config file loading/initializtion
#
module Owasp

  class Configuration
    def ids?
      return true
    end
  end

  class Logger
    def warn(msg)
      puts "WARNING: #{msg}"
    end
  end

  module Esapi

    def self.security_config
      @security ||= Configuration.new
    end
    def self.logger
      @logger ||= Logger.new
    end

  end
end