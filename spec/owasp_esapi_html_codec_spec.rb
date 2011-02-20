require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

module Owasp
  module Esapi
      module Codec
        describe Codec do
          let (:codec) { Owasp::Esapi::Codec::HtmlCodec.new }

          it "should not change test" do
            codec.encode([],"test").should == "test"
          end

          it "should encode < as &lt;" do
            codec.encode([],"<").should == "&lt;"
          end

          it "should encode 0x100 as &#x100;" do
            s = 0x100.chr(Encoding::UTF_8)
            m = codec.encode([],s[0])
            m.should == "&#x100;"
          end

          it "should decode &#x74;&#x65;&#x73;&#x74;! as test!" do
            codec.decode("&#x74;&#x65;&#x73;&#x74;!").should == "test!"
          end

          it "should skip &jeff; an invlaid attribute" do
            codec.decode("&jeff;").should == "&jeff;"
          end

          it "should decode &amp; as &" do
            codec.decode("&amp;").should == "&"
            codec.decode("&amp;X").should == "&X"
            codec.decode("&amp").should == "&"
            codec.decode("&ampX").should == "&X"
          end

          it "should decode &lt; as <" do
            codec.decode("&lt;").should == "<"
            codec.decode("&lt;X").should == "<X"
            codec.decode("&lt").should == "<"
            codec.decode("&ltX").should == "<X"
            codec.decode("&#60").should == "<"
          end

          it "should decode &sup2" do
            codec.decode("&sup2;").should == "\u00B2"
            codec.decode("&sup2;X").should == "\u00B2X"
            codec.decode("&sup2").should == "\u00B2"
            codec.decode("&sup2X").should == "\u00B2X"
          end

          it "should decode &sup3" do
            codec.decode("&sup3;").should == "\u00B3"
            codec.decode("&sup3;X").should == "\u00B3X"
            codec.decode("&sup3").should == "\u00B3"
            codec.decode("&sup3X").should == "\u00B3X"
          end

          it "should decode &sup1" do
            codec.decode("&sup1;").should == "\u00B9"
            codec.decode("&sup1;X").should == "\u00B9X"
            codec.decode("&sup1").should == "\u00B9"
            codec.decode("&sup1X").should == "\u00B9X"
          end

          it "should decode &sup" do
            codec.decode("&sup;").should == "\u2283"
            codec.decode("&sup;X").should == "\u2283X"
            codec.decode("&sup").should == "\u2283"
            codec.decode("&supX").should == "\u2283X"
          end

          it "should decode &supe" do
            codec.decode("&supe;").should == "\u2287"
            codec.decode("&supe;X").should == "\u2287X"
            codec.decode("&supe").should == "\u2287"
            codec.decode("&supeX").should == "\u2287X"
          end

          it "should decode &pi" do
            codec.decode("&pi;").should == "\u03C0"
            codec.decode("&pi;X").should == "\u03C0X"
            codec.decode("&pi").should == "\u03C0"
            codec.decode("&piX").should == "\u03C0X"
          end

          it "should decode &piv" do
            codec.decode("&piv;").should == "\u03D6"
            codec.decode("&piv;X").should == "\u03D6X"
            codec.decode("&piv").should == "\u03D6"
            codec.decode("&pivX").should == "\u03D6X"
          end

          it "should decode &theta" do
            codec.decode("&theta;").should == "\u03B8"
            codec.decode("&theta;X").should == "\u03B8X"
            codec.decode("&theta").should == "\u03B8"
            codec.decode("&thetaX").should == "\u03B8X"
          end

          it "should decode &thetasym" do
            codec.decode("&thetasym;").should == "\u03D1"
            codec.decode("&thetasym;X").should == "\u03D1X"
            codec.decode("&thetasym").should == "\u03D1"
            codec.decode("&thetasymX").should == "\u03D1X"
          end

        end
      end
    end
end