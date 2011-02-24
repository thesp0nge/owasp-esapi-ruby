require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

module Owasp
  module Esapi
    module Codec
      describe Codec do
        let (:codec) { Owasp::Esapi::Codec::VbScriptCodec.new }
        it "should encode < as chrw(60)" do
          codec.encode_char([],"<").should == "chrw(60)"
        end
        it "should encode 0x100 as \\u0100" do
          s = 0x100.chr(Encoding::UTF_8)
          codec.encode_char([],s[0]).should == "chrw(256)"
        end

        it "should decode '\"<' as <" do
          codec.decode("\"<").should == "<"
        end

      end
    end
  end
end
