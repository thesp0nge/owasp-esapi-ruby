require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

module Owasp
  module Esapi
      module Validator
        describe Zipcode do
          let(:validator) {Owasp::Esapi::Validator::Zipcode.new}
          
          it "should validate a good US ZIP CODE" do
            validator.valid?("12345").should == true
          end
          
          it "should validate a good US ZIP CODE" do
            validator.valid?("12345-6789").should == true
          end
          
          it "should discard a bad US ZIP CODE" do
            validator.valid?("foostring").should == false
          end
          
          it "should discard a bad US ZIP CODE" do 
            validator.valid?("123-323").should == false
          end
          
          it "should validate a good Italian ZIP CODE equivalent" do
            validator.matcher=Owasp::Esapi::Validator::Zipcode::ITALIAN_ZIPCODE
            validator.valid?("20100").should == true
          end
          
          it "should discard an invalid Italian ZIP CODE equivalent" do
            validator.matcher=Owasp::Esapi::Validator::Zipcode::ITALIAN_ZIPCODE
            validator.valid?("121").should == false
          end
          it "should discard an invalid Italian ZIP CODE equivalent" do
            validator.matcher=Owasp::Esapi::Validator::Zipcode::ITALIAN_ZIPCODE
            validator.valid?("ipse dixit").should == false
          end
        end
      end
    
  end
end