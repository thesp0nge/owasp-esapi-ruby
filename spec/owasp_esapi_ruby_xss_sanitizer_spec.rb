require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

module Owasp
  module Esapi
    module Ruby
      module Xss
        describe Sanitizer do
          let(:filter) {Owasp::Esapi::Ruby::Xss::Sanitizer.new}
          
          it "should leave untouched untainted strings" do
            untainted = "This is an unoffensive string"
            output = filter.sanitize(untainted)
            output.should == untainted
          end
          
          it "should sanitize '<' character " do
            false_positive_tainted = "I am a supposed to be a tainted < string"
            output = filter.sanitize(false_positive_tainted)
            output.should == false_positive_tainted.gsub("<", "&lt;")
          end
        end
      end
    end
  end
end