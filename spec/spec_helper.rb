$LOAD_PATH.unshift(File.dirname(__FILE__))
$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), '..', 'lib'))

require 'owasp-esapi-ruby'
require 'rspec'
require 'rspec/autorun'

Owasp::Esapi.security_config.resources["antisamy"] = "#{File.dirname(__FILE__)}/antisamy-esapi.xml"

RSpec.configure do |config|
  config.color_enabled = true
end
