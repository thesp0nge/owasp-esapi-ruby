require File.expand_path(File.dirname(__FILE__) + '../../spec_helper')

module Owasp
  module Esapi
    module Codec
      describe OsCodec do
        let(:unix_codec) {Owasp::Esapi::Codec::OsCodec.new( Owasp::Esapi::Codec::OsCodec::UNIX_HOST)}
        let(:win_codec) {Owasp::Esapi::Codec::OsCodec.new( Owasp::Esapi::Codec::OsCodec::WINDOWS_HOST)}

        it "should detect the actual host os" do
          codec = Owasp::Esapi::Codec::OsCodec.new
          codec.os.should == Owasp::Esapi::Codec::OsCodec::UNIX_HOST
        end

        it "should decode ^< as < for windows" do
          win_codec.decode("^<").should == "<"
        end

        it "should decode \\< as < for unix" do
          unix_codec.decode("\\<").should == "<"
        end

        it "should encode c:\\jeff with ^ chars for windows" do
          win_codec.encode([],"C:\\jeff").should == "C^:^\\jeff"
        end

        it "should encode dir & foo with ^ chars for windows" do
          win_codec.encode([],"dir & foo").should == "dir^ ^&^ foo"

        end

        it "should encode c:\\jeff with \\ chars for unix" do
          unix_codec.encode(Owasp::Esapi::Encoder::CHAR_ALPHANUMERIC,"C:\\jeff").should == "C\\:\\\\jeff"
        end

        it "should encode dir & foo with \\ chars for unix" do
          unix_codec.encode([],"dir & foo").should == "dir\\ \\&\\ foo"
        end

        it "should encode /etc/hosts with \\ chars for unix" do
          unix_codec.encode(['-'],"/etc/hosts").should == "\\/etc\\/hosts"
        end

        it "should encode /etc/hosts; ls -l with \\ chars for unix" do
          unix_codec.encode(['-'],"/etc/hosts; ls -l").should == "\\/etc\\/hosts\\;\\ ls\\ -l"
        end

      end
    end
  end
end
