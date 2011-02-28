require File.expand_path(File.dirname(__FILE__) + '../../spec_helper')

module Owasp
  module Esapi
    module Codec
      describe XmlCodec do
        let (:codec) { Owasp::Esapi::Codec::XmlCodec.new }
        describe 'XML encoding' do
          it "should encode nil as nil" do
            codec.encode([],nil).should == nil
          end

          it "should encode ' ' as ' '" do
            codec.encode(Owasp::Esapi::Encoder::IMMUNE_XML," ").should == " "
          end

          it "should encode <script> as &#x3c;script&#x3e;" do
            codec.encode(Owasp::Esapi::Encoder::IMMUNE_XML,"<script>").should == "&#x3c;script&#x3e;"
          end

          it "should encode ,.-_ as same" do
            codec.encode(Owasp::Esapi::Encoder::IMMUNE_XML,",.-_").should == ",.-_"
          end

          it "should encode !@$%()=+{}[] as &#x21;&#x40;&#x24;&#x25;&#x28;&#x29;&#x3d;&#x2b;&#x7b;&#x7d;&#x5b;&#x5d;" do
            codec.encode(Owasp::Esapi::Encoder::IMMUNE_XML,"!@$%()=+{}[]").should == "&#x21;&#x40;&#x24;&#x25;&#x28;&#x29;&#x3d;&#x2b;&#x7b;&#x7d;&#x5b;&#x5d;"
          end

          it "should encode \u00A3 as &#xa3;" do
            codec.encode(Owasp::Esapi::Encoder::IMMUNE_XML,"\u00A3").should == "&#xa3;"
          end
        end

        describe 'Attributes Encoding' do
          it "should encode ' ' as ' '" do
            codec.encode(Owasp::Esapi::Encoder::IMMUNE_XMLATTR," ").should == " "
          end

          it "should encode <script> as &#x3c;script&#x3e;" do
            codec.encode(Owasp::Esapi::Encoder::IMMUNE_XMLATTR,"<script>").should == "&#x3c;script&#x3e;"
          end

          it "should encode ,.-_ as same" do
            codec.encode(Owasp::Esapi::Encoder::IMMUNE_XMLATTR,",.-_").should == ",.-_"
          end

          it "should encode !@$%()=+{}[] as &#x21;&#x40;&#x24;&#x25;&#x28;&#x29;&#x3d;&#x2b;&#x7b;&#x7d;&#x5b;&#x5d;" do
            codec.encode(Owasp::Esapi::Encoder::IMMUNE_XMLATTR,"!@$%()=+{}[]").should == "&#x21;&#x40;&#x24;&#x25;&#x28;&#x29;&#x3d;&#x2b;&#x7b;&#x7d;&#x5b;&#x5d;"
          end

          it "should encode \u00A3 as &#xa3;" do
            codec.encode(Owasp::Esapi::Encoder::IMMUNE_XMLATTR,"\u00A3").should == "&#xa3;"
          end
        end

        describe 'Decoding' do
          {
            "AB_YZ" => "AB_YZ",
            "AB&gt;YZ" => "AB>YZ",
            "AB&amp;YZ" => "AB&YZ",
            "AB&quot;YZ" => "AB\"YZ",
            "AB&apos;YZ" => "AB'YZ",
            "AB&quot;" => "AB\"",
            "&quot;YZ" => "\"YZ",
            "&quot;" => "\"",
            "AB&quot" => "AB&quot",
            "&quotYZ" => "&quotYZ",
            "&quot" => "&quot",
            "AB&pound;" => "AB&pound;",
            "&pound;YZ" => "&pound;YZ",
            "&pound;" => "&pound;",
            "AB&#64;YZ" => "AB@YZ",
            "AB&#x40;YZ" => "AB@YZ"
          }.each_pair do |k,v|
            it "should decode #{k} as #{v}" do
              codec.decode(k).should == v
            end
          end
        end
      end
    end
  end
end
