require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

module Owasp
  module Esapi
      module Codec
        describe Codec do
          let (:codec) { Owasp::Esapi::Codec::CssCodec.new }

          it "should encode my '<' as \\3c" do
            m = codec.encode([],"<")
            m.should == '\\3c'
          end

          it "should encode 0x100 as \\100" do
            s = 0x100
            m = codec.encode([],s)
            m.should == "\\100"
          end

          it "should decode '\\<' to '<'" do
            m = codec.decode("\\<")
            m.should == "<"
          end

          it "should decode '\\41xyz' to Axyz" do
            m = codec.decode("\\41xyz")
            m.should == "Axyz"
          end

          it "should decode '\\000041abc' to 'Aabc'" do
            m = codec.decode("\\000041abc")
            m.should == "Aabc"
          end

          it "should decode '\\41 abc' to 'Aabc'" do
            m = codec.decode("\\41 abc")
            m.should == "Aabc"
          end

          it "should decode 'abc\\\nxyz' to 'abcxyz'" do
            m = codec.decode("abc\\\nxyz")
            m.should == "abcxyz"
          end

          it "should decode 'abc\\\r\nxyz' to 'abcxyz'" do
            m = codec.decode("abc\\\r\nxyz")
            m.should == "abcxyz"
          end

        end
      end
  end
end