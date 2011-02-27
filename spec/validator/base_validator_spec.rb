require File.expand_path(File.dirname(__FILE__) + '../../spec_helper')

module Owasp
  module Esapi
    module Validator
      describe BaseValidator do
        let(:rule) {Owasp::Esapi::Validator::BaseValidator.new("test")}
        it "should remove non whitelist characters" do
          rule.whitelist("12345abcdefghijkmlaaaa","abc").should == "abcaaaa"
        end

        it "should raise and exception in the base class" do
          lambda {rule.valid("test","input")}.should raise_error(Owasp::Esapi::ValidationException)
        end

        it "should return false for valid? int eh base rule" do
          rule.valid?("test","input").should be_false
        end

        it "should has an item in the error list" do
          v = Owasp::Esapi::Validator::ValidatorErrorList.new
          rule.validate("context","input",v)
          v.errors.should_not be_empty
        end

      end
    end
  end
end
