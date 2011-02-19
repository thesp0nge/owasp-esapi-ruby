require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

module Owasp
  module Esapi
    module Validator
      describe Date do
        let(:validator) {Owasp::Esapi::Validator::Date.new}
        
        it "should evaluate a good month digit" do
          validator.is_valid_month?(12).should == true
        end
        
        it "should evaluate a good month digit" do
          validator.is_valid_month?(0).should == false
        end
        
        it "should evaluate a good month digit" do
          validator.is_valid_month?(14).should == false
        end
        
        it "should evaluate a good day digit" do
          validator.is_valid_day?(12,12, 2010).should == true
        end
        
        it "should evaluate a good month digit" do
          validator.is_valid_day?(12, 6, 2011).should == true
        end
        
        it "should evaluate a good month digit" do
          validator.is_valid_day?(29, 2, 2011).should == false
        end
        
        it "should evaluate a good month digit" do
          validator.is_valid_day?(31, 4, 2011).should == false
        end
        
        it "should evaluate a good month digit" do
          validator.is_valid_day?(35, 3, 2011).should == false
        end
        
        it "should evaluate a good year digit" do
          validator.is_valid_year?(2011).should == true
        end
        
        it "should evaluate a good year digit" do
          validator.is_valid_year?(-322).should == false
        end
        
        it "should validate a good date (US Format)" do
          validator.matcher=Owasp::Esapi::Validator::Date::US_FORMAT_NUMERIC
          validator.valid?("12/31/2010").should == true
        end
        
        it "should discard a bad date (US Format)"  do
          validator.matcher=Owasp::Esapi::Validator::Date::US_FORMAT_NUMERIC
          validator.valid?("12/33/2010").should == false
        end
        
        it "should validate a good date (US Format)" do
          validator.matcher=Owasp::Esapi::Validator::Date::US_FORMAT_STRING_SHORT
          validator.valid?("Jan 15, 2011").should == true
        end
        
        it "should discard a bad date (US Format)" do
          validator.matcher=Owasp::Esapi::Validator::Date::US_FORMAT_STRING_SHORT
          validator.valid?("Jan 15 2011").should == false
        end
        
        it "should discard a bad date (US Format)" do
          validator.matcher=Owasp::Esapi::Validator::Date::US_FORMAT_STRING_SHORT
          validator.valid?("Jan, 15 2011").should == false
        end
        
        it "should discard a bad date (US Format)" do
          validator.matcher=Owasp::Esapi::Validator::Date::US_FORMAT_STRING_SHORT
          validator.valid?("Jan a, 2011").should == false
        end
        
        it "should discard a bad date (US Format)" do
          validator.matcher=Owasp::Esapi::Validator::Date::US_FORMAT_STRING_SHORT
          validator.valid?("Jan 32, 2011").should == false
        end
        
        it "should validate a good date (US Format)" do
          validator.matcher=Owasp::Esapi::Validator::Date::US_FORMAT_STRING_LONG
          validator.valid?("January 15, 2011").should == true
        end
        
        it "should discard a bad date (US Format)" do
          validator.matcher=Owasp::Esapi::Validator::Date::US_FORMAT_STRING_LONG
          validator.valid?("January 15 2011").should == false
        end
        
        it "should discard a bad date (US Format)" do
          validator.matcher=Owasp::Esapi::Validator::Date::US_FORMAT_STRING_LONG
          validator.valid?("January, 15 2011").should == false
        end
        
        it "should discard a bad date (US Format)" do
          validator.matcher=Owasp::Esapi::Validator::Date::US_FORMAT_STRING_LONG
          validator.valid?("January a, 2011").should == false
        end
        
        it "should discard a bad date (US Format)" do
          validator.matcher=Owasp::Esapi::Validator::Date::US_FORMAT_STRING_LONG
          validator.valid?("January 32, 2011").should == false
        end
        
        it "should validate a good date (US Format)" do
          validator.matcher=Owasp::Esapi::Validator::Date::US_FORMAT_STRING_SHORT
          validator.valid?("Feb, 29 2012").should == false
        end
        
        it "should discard a bad date (US Format)" do
          validator.matcher=Owasp::Esapi::Validator::Date::US_FORMAT_STRING_SHORT
          validator.valid?("Feb, 29 2011").should == false
        end
        
        it "should validate a good date (US Format)" do
          validator.matcher=Owasp::Esapi::Validator::Date::US_FORMAT_STRING_LONG
          validator.valid?("February, 29 2012").should == false
        end
        
        it "should discard a bad date (US Format)" do
          validator.matcher=Owasp::Esapi::Validator::Date::US_FORMAT_STRING_LONG
          validator.valid?("February, 29 2011").should == false
        end
        
        it "should validate a good date (EU Format)" do
          validator.matcher=Owasp::Esapi::Validator::Date::EU_FORMAT_NUMERIC
          validator.eu_format = true
          validator.valid?("31/12/2010").should == true
        end
        
        it "should discard a bad date (US Format)"  do
          validator.matcher=Owasp::Esapi::Validator::Date::EU_FORMAT_NUMERIC
          validator.eu_format = true
          validator.valid?("33/12/2010").should == false
        end
        
        it "should discard a bad date (US Format)"  do
          validator.matcher=Owasp::Esapi::Validator::Date::EU_FORMAT_NUMERIC
          validator.eu_format = true
          validator.valid?("31/13/2010").should == false
        end
        
      end
    end
  end
end