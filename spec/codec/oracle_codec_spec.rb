require File.expand_path(File.dirname(__FILE__) + '../../spec_helper')

module Owasp
  module Esapi
    module Codec
      describe OracleCodec do
        let (:codec) { Owasp::Esapi::Codec::OracleCodec.new }

        it "should encode eddie's stuff as eddie''s stuff" do
          codec.encode([],"eddie's stuff").should == "eddie''s stuff"
        end
        it "should encode \' as \'\'" do
          codec.encode([],"\'").should == "\'\'"
        end

        it "should decode \'\' as \'" do
          codec.decode("\'\'").should == "\'"
        end

      end
    end
  end
end
