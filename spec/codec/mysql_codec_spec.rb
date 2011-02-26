require File.expand_path(File.dirname(__FILE__) + '../../spec_helper')

module Owasp
  module Esapi
    module Codec
      describe MySQLCodec do
        let (:ansi_codec) { Owasp::Esapi::Codec::MySQLCodec.new(Owasp::Esapi::Codec::MySQLCodec::ANSI_MODE) }
        let (:mysql_codec) { Owasp::Esapi::Codec::MySQLCodec.new(Owasp::Esapi::Codec::MySQLCodec::MYSQL_MODE) }
        let (:big_char) {  }

        it "should encode \' as \'\' in ANSI mode" do
          ansi_codec.encode([],"\'").should == "\'\'"
        end

        it "should encode < as \\< in MYSQL mode" do
          mysql_codec.encode([],"<").should == "\\<"
        end

        it "should encode 0x100 as \\0x100 in MYSQL mode" do
          s = 0x100.chr(Encoding::UTF_8)[0]
          mysql_codec.encode([],s) == "\\#{s}"
        end

        it "should encode 0x100 as 0x100 in ANSI mode" do
          s = 0x100.chr(Encoding::UTF_8)[0]
          ansi_codec.encode([],s) == "#{s}"
        end

        it "should decode '' as ' in ANSI mode" do
          ansi_codec.decode("\'\'").should == "\'"
        end

        it "should decode \\< as < in MYSQL mode" do
          mysql_codec.decode("\\<").should == "<"
        end

        it "should fail to create a code with an invalid mode" do
          lambda { Owasp::Esapi::Codec::MySQLCodec.new(5)}.should raise_error(RangeError)
        end

      end
    end
  end
end
