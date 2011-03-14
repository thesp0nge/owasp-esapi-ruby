require File.expand_path(File.dirname(__FILE__) + '../../spec_helper')

module Owasp
  module Esapi
    module Validator
      describe HTMLRule do
        let(:rule) {Owasp::Esapi::Validator::HTMLRule.new("test")}

        it "shuld clean out unsafe HTML" do
          rule.valid("test","Test. <script>alert(document.cookie)</script>").should == "Test."
        end

        it "should string bold tags off of <b>jeff</b>" do
          rule.valid("test","<b>Jeff</b>").should == "Jeff"
        end
        it "should leave the link alone according to the test rules" do
          input = "<a href=\"http://www.aspectsecurity.com\">Aspect Security</a>"
          rule.valid("test",input).should == input
        end

        it "should remove the escaped div" do
          input = "Test. <<div on<script></script>load=alert()"
          rule.valid("test",input).should == "Test. load=alert()"
        end

        it "should clean out the expression" do
          input = "Test. <div style={xss:expression(xss)}>b</div>"
          rule.valid("test",input).should == "<p>Test. </p><div>b</div>"
        end

        it "should clean out the script" do
          input = "Test. <s%00cript>alert(document.cookie)</script>"
          rule.valid("test",input).should == "Test."
        end

        it "should remove the escaped script" do
          input = "Test. <s\tcript>alert(document.cookie)</script>"
          rule.valid("test",input).should == "Test. alert(document.cookie)"
        end

      end
    end
  end
end
