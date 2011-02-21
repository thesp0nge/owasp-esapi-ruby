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

module Owasp
  class Configuration
    attr_accessor :logger, :encoder
    def ids?
      return true
    end
    def get_encoder_class

    end
  end

  class Logger
    def warn(msg)
      puts "WARNING: #{msg}"
    end
  end

  module Esapi

    # seutp ESAPI
    def self.setup
      @config ||= Configuration.new
      yield @config if block_given?
      process_config(@config)
    end


    def self.security_config
      @security ||= Configuration.new
    end
    def self.logger
      @logger ||= Logger.new
    end
    def self.encoder
      @encoder ||= ClassLoader.load_class("Owasp::Esapi::Encoder")
    end

    private
    # Process the config data to setup esapi
    def self.process_config(conf)
    end

  end
end