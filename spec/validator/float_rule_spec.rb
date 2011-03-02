require File.expand_path(File.dirname(__FILE__) + '../../spec_helper')

module Owasp
  module Esapi
    module Validator
      describe FloatRule do

        it "should validate 4.3214 as valid within range of -10 to 10" do
          rule = Owasp::Esapi::Validator::FloatRule.new("test",nil,-10,10)
          rule.valid?("","4.3214").should be_true
        end

        it "should fail to validate -1 for range of 0 to 100" do
          rule = Owasp::Esapi::Validator::FloatRule.new("test",nil,0,100)
          rule.valid?("","-1").should be_false
        end

        it "should not validate 1e-6 as valid within range of -999999999 to 999999999" do
          rule = Owasp::Esapi::Validator::FloatRule.new("test",nil,-999999999,999999999)
          rule.valid?("","1e-6").should be_true
        end

        it "should raise an error when a non string is passed in" do
          rule = Owasp::Esapi::Validator::FloatRule.new("test",nil,0,300)
          lambda{ rule.valid("","#{Float::INFINITY}") }.should raise_error(ValidationException)
        end

      end
    end
  end
end
