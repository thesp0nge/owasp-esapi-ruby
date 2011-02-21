require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

module Owasp
  module Esapi
    module Codec
      describe Codec do
        it "should detect the actual host os" do
          codec = Owasp::Esapi::Codec::OsCodec.new
          codec.os.should == Owasp::Esapi::Codec::OsCodec::UNIX_HOST
        end
        it "should decode ^< as < for windows" do
          codec = Owasp::Esapi::Codec::OsCodec.new( Owasp::Esapi::Codec::OsCodec::WINDOWS_HOST)
          codec.decode("^<").should == "<"
        end

        it "should decode \\< as < for unix" do
          codec = Owasp::Esapi::Codec::OsCodec.new( Owasp::Esapi::Codec::OsCodec::UNIX_HOST)
          codec.decode("\\<").should == "<"
        end

        it "should encode paths properly for windows" do
          codec = Owasp::Esapi::Codec::OsCodec.new( Owasp::Esapi::Codec::OsCodec::WINDOWS_HOST)
          codec.encode([],"C:\\jeff").should == "C^:^\\jeff"
          codec.encode([],"dir & foo").should == "dir^ ^&^ foo"

        end

        it "should encode paths properly for unix" do
          codec = Owasp::Esapi::Codec::OsCodec.new( Owasp::Esapi::Codec::OsCodec::UNIX_HOST)
          codec.encode(Owasp::Esapi::Encoder::CHAR_ALPHANUMERIC,"C:\\jeff").should == "C\\:\\\\jeff"
          codec.encode([],"dir & foo").should == "dir\\ \\&\\ foo"
          codec.encode(['-'],"/etc/hosts").should == "\\/etc\\/hosts"
          codec.encode(['-'],"/etc/hosts; ls -l").should == "\\/etc\\/hosts\\;\\ ls\\ -l"
        end

      end
    end
  end
end
