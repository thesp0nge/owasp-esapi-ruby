require File.expand_path(File.dirname(__FILE__) + '../../spec_helper')

module Owasp
  module Esapi
    module Validator
      describe IntegerRule do

        it "should validate 89745 as valid within range of 0 to 1000000" do
          rule = Owasp::Esapi::Validator::IntegerRule.new("test",nil,0,10000000)
          rule.valid?("","89745").should be_true
        end

        it "should fail to validate -1 for range of 0 to 100" do
          rule = Owasp::Esapi::Validator::IntegerRule.new("test",nil,0,100)
          rule.valid?("","-1").should be_false
        end

        it "should validate 0x100 as valid within range of 0 to 300" do
          rule = Owasp::Esapi::Validator::IntegerRule.new("test",nil,0,300)
          rule.valid("","0x100").should == 256
        end

        it "should raise an error when a non string is passed in" do
          rule = Owasp::Esapi::Validator::IntegerRule.new("test",nil,0,300)
          lambda{ rule.valid("",100) }.should raise_error(TypeError)
        end

        it "should validate 0100 as an octal and with range for 0 to 65" do
          rule = Owasp::Esapi::Validator::IntegerRule.new("test",nil,0,65)
          rule.valid("","0100").should == 64
        end

        it "should validate a bit string 0b0001 as 1 within range of 0 to 2" do
          rule = Owasp::Esapi::Validator::IntegerRule.new("test",nil,0,2)
          rule.valid("","0b0001").should == 1
        end

        it "should fail to validate testme as a number within any range" do
          rule = Owasp::Esapi::Validator::IntegerRule.new("test",nil,0,2)
          rule.valid?("","testme").should be_false
        end

        it "should validate -1 within range of -5 t0 5" do
          rule = Owasp::Esapi::Validator::IntegerRule.new("test",nil,-5,5)
          rule.valid?("","-1").should be_true
        end

      end
    end
  end
end
