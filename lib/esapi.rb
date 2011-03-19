#
# Class loading mechanism, we use this to create new instances of objects based
# on config data. This allows a user to set their own config for instance to use thier
# own implmentation of a given class. ClassLoader based on Rails constantize
#
class ClassLoader
  def self.load_class(class_name)
    # we are using ruby 1.9.2 as a requirement, so we can use the inheritance
    # of const_get to find our object. if mis-spelled it will raise a NameError
    names = class_name.split("::")
    klass = Object
    names.each do |name|
      klass = klass.const_get(name)
    end
    klass.new
  end
end

# Owasp root modules
module Owasp
  # Configuration class
  class Configuration
    attr_accessor :logger, :encoder, :resources

    def initialize
      @resources = {}
      @patterns = {}
    end
    # Is intrustion detectione nabled?
    def ids?
      return true
    end
    # Get the encoder class anem
    def get_encoder_class
    end
    def resource(resource_key)
      return @resources[resource_key]
    end
    def pattern(name)
      @patterns[name]
    end
    def add_pattern(name,regex)
      @patterns[name] = regex
    end

  end
  # Logging class stub
  class Logger
    def warn(msg)
      #puts "WARNING: #{msg}"
    end
    def info(level,msg)
    end
  end
  # Esapi Root module
  module Esapi

    # seutp ESAPI
    def self.setup
      @config ||= Configuration.new
      yield @config if block_given?
      process_config(@config)
    end

    # Get the security configuration context
    def self.security_config
      @security ||= Configuration.new
    end
    # Get the configured logger
    def self.logger
      @logger ||= Logger.new
    end
    # Get the configured encoded
    def self.encoder
      @encoder ||= ClassLoader.load_class("Owasp::Esapi::Encoder")
    end

    private
    # Process the config data to setup esapi
    def self.process_config(conf)
    end

  end
end
