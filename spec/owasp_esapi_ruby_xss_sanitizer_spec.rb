require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

module Owasp
  module Esapi
    module Ruby
      module Sanitizer
        describe Xss do
          let(:filter) {Owasp::Esapi::Ruby::Sanitizer::Xss.new}
          
          it "should leave untouched untainted strings" do
            untainted = "This is an unoffensive string"
            output = filter.sanitize(untainted)
            output.should == untainted
          end
          
          it "should sanitize the '<' character" do
            false_positive_tainted = "I am a supposed to be a tainted < string"
            output = filter.sanitize(false_positive_tainted)
            output.should == false_positive_tainted.gsub("<", "&lt;")
          end
          
          it "should sanitize the '>' character" do
            false_positive_tainted = "I am a supposed to be a tainted > string"
            output = filter.sanitize(false_positive_tainted)
            output.should == false_positive_tainted.gsub(">", "&gt;")
          end
          
          it "should sanitize the '&' character" do
            false_positive_tainted = "I am a supposed to be a tainted & string"
            output = filter.sanitize(false_positive_tainted)
            output.should == false_positive_tainted.gsub("&", "&amp;")
          end
          
          it "should sanitize the '\"' character" do
            false_positive_tainted = "I am a supposed to be a tainted \" string"
            output = filter.sanitize(false_positive_tainted)
            output.should == false_positive_tainted.gsub("\"", "&quot;")
          end
          
          it "should sanitize the '\'' character" do
            false_positive_tainted = "I am a supposed to be a tainted \' string"
            output = filter.sanitize(false_positive_tainted)
            output.should == false_positive_tainted.gsub("\'", "&#x27;")
          end
          
          it "should sanitize the '/' character" do
            false_positive_tainted = "I am a supposed to be a tainted / string"
            output = filter.sanitize(false_positive_tainted)
            output.should == false_positive_tainted.gsub("/", "&#x2F;")
          end
          
          it "shoud sanitize an injecting up attack pattern" do
            taint = "<script>alert('xss here');</script>"
            output = filter.sanitize(taint)
            output.should == taint.gsub("<", "&lt;").gsub(">", "&gt;").gsub("\'", "&#x27;").gsub("/", "&#x2F;")
          end
          
          it "shoud sanitize an injecting up attack pattern" do
            taint = "/><script>alert('xss here');</script>"
            output = filter.sanitize(taint)
            output.should == taint.gsub("<", "&lt;").gsub(">", "&gt;").gsub("\'", "&#x27;").gsub("/", "&#x2F;")
          end
        end
      end
    end
  end
end