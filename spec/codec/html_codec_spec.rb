require File.expand_path(File.dirname(__FILE__) + '../../spec_helper')

module Owasp
  module Esapi
      module Codec
        describe HtmlCodec do
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

          # dynamic tests for various inputs to decode
          {
           "&amp;" => "&",
           "&amp;X" => "&X",
           "&amp" => "&",
           "&ampX" => "&X",
           "&lt;" => "<",
            "&lt;X" => "<X",
            "&lt" => "<",
            "&ltX"=> "<X",
            "&#60" => "<",
            "&sup2;" => "\u00B2",
            "&sup2;X" => "\u00B2X",
            "&sup2" => "\u00B2",
            "&sup2X" => "\u00B2X",
            "&sup3;" => "\u00B3",
            "&sup3;X" => "\u00B3X",
            "&sup3" => "\u00B3",
            "&sup3X" => "\u00B3X",
            "&sup1;" => "\u00B9",
            "&sup1;X" => "\u00B9X",
            "&sup1" => "\u00B9",
            "&sup1X" => "\u00B9X",
            "&sup;" => "\u2283",
            "&sup;X" => "\u2283X",
            "&sup" => "\u2283",
            "&supX" => "\u2283X",
            "&supe;" => "\u2287",
            "&supe;X" => "\u2287X",
            "&supe" => "\u2287",
            "&supeX" => "\u2287X",
            "&pi;" => "\u03C0",
            "&pi;X" => "\u03C0X",
            "&pi" => "\u03C0",
            "&piX" => "\u03C0X",
            "&piv;" => "\u03D6",
            "&piv;X" => "\u03D6X",
            "&piv" => "\u03D6",
            "&pivX" => "\u03D6X",
            "&theta;" => "\u03B8",
            "&theta;X" => "\u03B8X",
            "&theta" => "\u03B8",
            "&thetaX" => "\u03B8X",
            "&thetasym;" => "\u03D1",
            "&thetasym;X" => "\u03D1X",
            "&thetasym" => "\u03D1",
            "&thetasymX" => "\u03D1X",
          }.each_pair do |k,v|
            it "should decode #{k} as #{v}" do
              codec.decode(k).should == v
            end
          end

        end
      end
    end
end