require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

module Owasp
  module Esapi
    module Ruby
      module Validator
        describe Zipcode do
          let(:validator) {Owasp::Esapi::Ruby::Validator::Zipcode.new}
          
          it "should validate a good US ZIP CODE" do
            validator.validate("12345").should == true
          end
          
          it "should validate a good US ZIP CODE" do
            validator.validate("12345-6789").should == true
          end
          
          it "should discard a bad US ZIP CODE" do
            validator.validate("foostring").should == false
          end
          
          it "should discard a bad US ZIP CODE" do 
            validator.validate("123-323").should == false
          end
          
          it "should validate a good Italian ZIP CODE equivalent" do
            validator.matcher=Owasp::Esapi::Ruby::Validator::Zipcode::ITALIAN_ZIPCODE
            validator.validate("20100").should == true
          end
        end
      end
    end
  end
end