require File.expand_path(File.dirname(__FILE__) + '../../spec_helper')

module Owasp
  module Esapi
    module Validator
      describe DateValidator do
        let(:rule) {Owasp::Esapi::Validator::DateValidator.new("test",nil,nil)}

        it "should validate September 11, 2001 as a valid" do
          rule.valid?("","September 11, 2001").should be_true
        end

        it "should fail to validate 9-11-2001 as valid with the default format" do
          rule.valid?("","9-11-2001").should be_false
        end

        it "should fail to validate with a null date" do
          rule.valid?("",nil).should be_false
        end

        it "should fail to validate with an empty string as the date" do
          rule.valid?("","").should be_false
        end

        # Try a few different date formats
        {
          "Jan 1, 07 Sun GMT" => "%b %d, %y %Z",
          "31-12-2010" => "%d-%m-%Y",
          "31-1-2010" => "%d-%m-%Y",
          "2010-02-27 15:00" => "%Y-%m-%d %H:%M"
        }.each_pair do |k,v|
          it "should validate #{k} as a valid date with #{v} as the format" do
            rule = Owasp::Esapi::Validator::DateValidator.new("test",nil,v)
            rule.valid?("",k).should be_true
          end
        end
      end
    end
  end
end
