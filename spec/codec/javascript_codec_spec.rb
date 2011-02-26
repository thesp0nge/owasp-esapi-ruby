require File.expand_path(File.dirname(__FILE__) + '../../spec_helper')

module Owasp
  module Esapi
      module Codec
        describe JavascriptCodec do
          let (:codec) { Owasp::Esapi::Codec::JavascriptCodec.new }

          it "should decode \\x3c as <" do
            codec.decode("\\x3c").should == "<"
          end

          it "should encode < as \\x3C" do
            codec.encode([],"<").should == "\\x3C"
          end

          it "should encode 0x100 as \\u0100" do
            s = 0x100.chr(Encoding::UTF_8)
            codec.encode([],s[0]).should == "\\u0100"
          end

          it "should encode <script> as \\x3Cscript\\x3E" do
            codec.encode(Owasp::Esapi::Encoder::IMMUNE_JAVASCRIPT,"<script>").should == "\\x3Cscript\\x3E"
          end

          it "should encoder !@$%()=+{}[] as \\x21\\x40\\x24\\x25\\x28\\x29\\x3D\\x2B\\x7B\\x7D\\x5B\\x5D" do
            codec.encode(Owasp::Esapi::Encoder::IMMUNE_JAVASCRIPT,"!@$%()=+{}[]").should == "\\x21\\x40\\x24\\x25\\x28\\x29\\x3D\\x2B\\x7B\\x7D\\x5B\\x5D"
          end

          it "shoudl encode ',.-_ ' as ',.\\x2D_\\x20'" do
            codec.encode(Owasp::Esapi::Encoder::IMMUNE_JAVASCRIPT,",.-_ ").should == ",.\\x2D_\\x20"
          end

          it "should decode \\f as \f" do
            codec.decode("\\f").should == "\f"
          end

          it "should decode \\b as \b" do
            codec.decode("\\b").should == "\b"
          end

        end
      end
  end
end