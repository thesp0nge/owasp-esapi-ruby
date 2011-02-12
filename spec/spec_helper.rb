$LOAD_PATH.unshift(File.dirname(__FILE__))
$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), '..', 'lib'))

require 'owasp-esapi-ruby'
require 'rspec'
require 'rspec/autorun'

RSpec.configure do |config|
  config.color_enabled = true
end
