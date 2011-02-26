require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

module Owasp
  module Esapi
      module Codec
        describe PrecentCodec do
          let (:codec) { Owasp::Esapi::Codec::PercentCodec.new }

          it "should decode %3c as <" do
            codec.decode("%3c").should == "<"
          end

          it "should encode < as %3C" do
            codec.encode([],"<").should == "%3C"
          end

          it "should encode 0x100 as %C4%80" do
            s = 0x100.chr(Encoding::UTF_8)
            codec.encode([],s[0]).should == "%C4%80"
          end

          it "should decode %25F as %F" do
            codec.decode("%25F").should == "%F"
          end

          it "should encode 'Stop!' said Fred as %27Stop%21%27+said+Fred" do
            codec.encode([],"'Stop!' said Fred").should == "%27Stop%21%27+said+Fred"
          end

        end
      end
  end
end