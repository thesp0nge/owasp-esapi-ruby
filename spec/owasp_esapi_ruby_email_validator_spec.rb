require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

module Owasp
  module Esapi
    module Validator
      describe Email do
        let(:validator) {Owasp::Esapi::Validator::Email.new}
          
        it "should discard invalid email addresses" do
          validator.valid?("this is not an email address").should == false
        end
      
        it "should discard invalid email addresses" do
          validator.valid?("12313.it").should == false
        end
        
        it "should discard invalid email addresses" do
          validator.valid?("thesp0nge_at_owasp_dot_org").should == false
        end
        
        it "should discard invalid email addresses" do
          validator.valid?("thesp0 nge@owasp.org").should == false
        end
          
        it "should discard invalid email addresses" do
          validator.valid?("thesp0nge@owasp..org").should == false
        end
        
        it "should discard invalid email addresses" do
          validator.valid?("thesp0nge@ow asp.org").should == false
        end
        
        it "should validate goot email addresses" do
          validator.valid?("thesp0nge@owasp.org").should == true 
        end
      end
    end
  end
end