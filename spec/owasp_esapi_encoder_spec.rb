require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

module Owasp
  module Esapi
    describe Encoder do
      # Setup some encoders
      let (:encoder) { Owasp::Esapi.encoder }
      let (:jsencoder) {Owasp::Esapi::Encoder.new([Owasp::Esapi::Codec::JavascriptCodec.new])}
      let (:cssencoder) {Owasp::Esapi::Encoder.new([Owasp::Esapi::Codec::CssCodec.new])}

      # HTML and Percent Codec tests
      # Generate dynamic canonicalization tests
      {
        "%25F"=> "%F",
        "%3c"=> "<",
        "%3C"=> "<",
        "%X1"=> "%X1",
        "&#60"=> "<",
        "&#060"=> "<",
        "&#0060"=> "<",
        "&#000060"=>"<",
        "&#0000060"=>"<",
        "&#60;"=> "<",
        "&#060;"=> "<",
        "&#0060;"=> "<",
        "&#000060;"=> "<",
        "&#0000060;"=> "<",
        "&#x3c"=> "<",
        "&#x03c"=> "<",
        "&#x0003c"=> "<",
        "&#x000003c"=> "<",
        "&#x00000003c"=> "<",
        "&#x3c;"=> "<",
        "&#x03c;"=> "<",
        "&#x003c;"=> "<",
        "&#x00003c;"=> "<",
        "&#x0000003c;"=> "<",
        "&#X03c"=> "<",
        "&#X3c"=> "<",
        "&#X0003c"=> "<",
        "&#X000003c"=> "<",
        "&#X00000003c"=> "<",
        "&#x3C"=> "<",
        "&#x03C"=> "<",
        "&#x0003C"=> "<",
        "&#x000003C"=> "<",
        "&#x00000003C"=> "<",
        "&#X3C"=> "<",
        "&#X03C"=> "<",
        "&#X0003C"=> "<",
        "&#X000003C"=> "<",
        "&#X00000003C"=> "<",
        "&lt"=> "<",
        "&LT"=> "<",
        "&Lt"=> "<",
        "&lT"=> "<",
        "&lt;"=> "<",
        "&LT;"=> "<",
        "&Lt;"=> "<",
        "&lT;"=> "<",
        "&#37;"=> "%",
        "&#37"=> "%",
        "&#37b"=> "%b",
        "%3Cscript%3Ealert%28%22hello%22%29%3B%3C%2Fscript%3E"=> "<script>alert(\"hello\");</script>",
        "%3Cscript&#x3E;alert%28%22hello&#34%29%3B%3C%2Fscript%3E"=> "<script>alert(\"hello\");</script>",
      }.each_pair do |k,v|
        it "should canonicalize #{k} to #{v}" do
          begin
            encoder.canonicalize(k.dup).should == v
          rescue IntrustionException =>e
            # if IDSis on we would throw an intrustion exception, other exceptions are real errors
          end
        end
      end

      # Javascript dynamic canonicilzation tests
      {
        "\\0"=> "\0",
        "\\b"=> "\b",
        "\\t"=> "\t",
        "\\n"=> "\n",
        "\\v"=> "\v",
        "\\f"=> "\f",
        "\\r"=> "\r",
        "\\'"=> "\'",
        "\\\""=> "\"",
        "\\\\"=> "\\",
        "\\<"=> "<",
      }.each_pair do |k,v|
         it "should canonicalize javascript #{k} to #{v}" do
            begin
              jsencoder.canonicalize(k.dup).should == v
            rescue IntrustionException =>e
              # if IDSis on we would throw an intrustion exception, other exceptions are real errors
            end
          end
      end
      # CSS dynamic canonicalization tests
      {
        "\\3c"=> "<",
        "\\03c"=> "<",
        "\\003c"=> "<",
        "\\0003c"=> "<",
        "\\00003c"=> "<",
        "\\3C"=> "<",
        "\\03C"=> "<",
        "\\003C"=> "<",
        "\\0003C"=> "<",
        "\\00003C"=> "<",
      }.each_pair do |k,v|
         it "should canonicalize CSS #{k} to #{v}" do
            begin
              cssencoder.canonicalize(k.dup).should == v
            rescue IntrustionException =>e
              # if IDSis on we would throw an intrustion exception, other exceptions are real errors
            end
          end
      end
      # Sanitize
      it "should sanitize input exceptions" do
        # test null value
        encoder.canonicalize(nil).should == nil
        # test exception paths
        encoder.sanitize("%25",true).should == '%'
        encoder.sanitize("%25",false).should == '%'
      end

      # Dynamic double canonicalization tests
      {
        "&#x26;lt&#59"=> "<",# double entity
        "%255c"=> "\\",      # double percent
        "%2525"=> "%" ,      #double percent
        "%26lt%3b"=> "<",    #double percent
        "%253c"=> "<",
        "%26lt%3b"=> "<",
        "&#x25;26"=> "&",
        "%%33%63"=> "<",
        "%%33c"=> "<",
        "%3%63"=> "<",
        "&&#108;t;"=> "<",
        "&%6ct;"=> "<",
        "%&#x33;c"=> "<",
        "%25 %2526 %26#X3c;script&#x3e; &#37;3Cscript%25252525253e"=> "% & <script> <script>",
        "%26lt; %26lt; &#X25;3c &#x25;3c %2526lt%253B %2526lt%253B %2526lt%253B"=> "< < < < < < <",
        "%253Cscript"=> "<script",
        "&#37;3Cscript"=> "<script",
      }.each_pair do |k,v|
        it "should properly handle #{k} with double canonicalization and return #{v}" do
          begin
            encoder.sanitize(k.dup,false).should == v
          rescue IntrustionException =>e
            # if IDSis on we would throw an intrustion exception, other exceptions are real errors
          end
        end
      end

      # Css Encoder
      it "should css encode nil as nil" do
        encoder.encode_for_css(nil).should == nil
      end

      it "should css encode <script> as '\\3cscript\\3e" do
        encoder.encode_for_css("<script>").should == "\\3c script\\3e "
      end

      it "should css encode punction properly" do
        result = encoder.encode_for_css("!@$%()=+{}[]")
        result.should == "\\21 \\40 \\24 \\25 \\28 \\29 \\3d \\2b \\7b \\7d \\5b \\5d "
      end

      # HTML Encoder
      {
        "<script>" => "&lt;script&gt;",
        "&lt;script&gt;"=>"&amp;lt&#x3b;script&amp;gt&#x3b;",
        "!@$%()=+{}[]" => "&#x21;&#x40;&#x24;&#x25;&#x28;&#x29;&#x3d;&#x2b;&#x7b;&#x7d;&#x5b;&#x5d;",
        ",.-_ " => ",.-_ ",
        "dir&" => "dir&amp;",
        "one&two" => "one&amp;two",
      }.each_pair do |k,v|
        it "should encode HTML #{k} as #{v}" do
          encoder.encode_for_html(k).should == v
        end
      end

      # HTML Attribute
      {
        "<script>" => "&lt;script&gt;",
        "&lt;script&gt;"=>"&amp;lt&#x3b;script&amp;gt&#x3b;",
        " !@$%()=+{}[]" => "&#x20;&#x21;&#x40;&#x24;&#x25;&#x28;&#x29;&#x3d;&#x2b;&#x7b;&#x7d;&#x5b;&#x5d;",
      }.each_pair do |k,v|
        it "should encode html attribute #{k} as #{v}" do
          encoder.encode_for_html_attr(k).should == v
        end
      end

      # JS Encoder
      it "should hs encode nil as nil" do
        encoder.encode_for_javascript(nil).should == nil
      end

      it "should js encode special characers" do
        encoder.encode_for_javascript("!@$%()=+{}[]").should == "\\x21\\x40\\x24\\x25\\x28\\x29\\x3D\\x2B\\x7B\\x7D\\x5B\\x5D"
      end
      it "should js encode ',.-_ '" do
        encoder.encode_for_javascript(",.-_ ").should == ",.\\x2D_\\x20"
      end
      it "should js encode a script tag" do
        encoder.encode_for_javascript("<script>").should == "\\x3Cscript\\x3E"
      end
    end
  end
end
