require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

module Owasp
  module Esapi
    describe Encoder do
      let (:encoder) { Owasp::Esapi::Encoder.new }

      # Sanitize
      it "should sanitize input" do
        # test null value
        encoder.canonicalize(nil).should == nil
        # test exception paths
        encoder.sanitize("%25",true).should == '%'
        encoder.sanitize("%25",false).should == '%'
        # test HTML, url and CSS codecs
        encoder.canonicalize("%25F").should == "%F"
        encoder.canonicalize("%3c").should == "<"
        encoder.canonicalize("%3C").should == "<"
        encoder.canonicalize("%X1").should == "%X1"
        encoder.canonicalize("%25F").should == "%F"
        encoder.canonicalize("%25F").should == "%F"
        encoder.canonicalize("%25F").should == "%F"
        encoder.canonicalize("%25F").should == "%F"
        encoder.canonicalize("%25F").should == "%F"
        encoder.canonicalize("%25F").should == "%F"
        encoder.canonicalize("%25F").should == "%F"
        encoder.canonicalize("%25F").should == "%F"
        encoder.canonicalize("%25F").should == "%F"
        encoder.canonicalize("%25F").should == "%F"
        encoder.canonicalize("%25F").should == "%F"
        encoder.canonicalize("%25F").should == "%F"
        encoder.canonicalize("%25F").should == "%F"
        encoder.canonicalize("\\3c").should == "<"
        encoder.canonicalize("\\03c").should == "<"
        encoder.canonicalize("\\003c").should == "<"
        encoder.canonicalize("\\0003c").should == "<"
        encoder.canonicalize("\\00003c").should == "<"
        encoder.canonicalize("\\3C").should == "<"
        encoder.canonicalize("\\03C").should == "<"
        encoder.canonicalize("\\003C").should == "<"
        encoder.canonicalize("\\0003C").should == "<"
        encoder.canonicalize("\\00003C").should == "<"
        encoder.canonicalize("&#60").should == "<"
        encoder.canonicalize("&#060").should == "<"
        encoder.canonicalize("&#0060").should == "<"
        encoder.canonicalize("&#000060").should == "<"
        encoder.canonicalize("&#0000060").should == "<"
        encoder.canonicalize("&#60;").should == "<"
        encoder.canonicalize("&#060;").should == "<"
        encoder.canonicalize("&#0060;").should == "<"
        encoder.canonicalize("&#000060;").should == "<"
        encoder.canonicalize("&#0000060;").should == "<"
        encoder.canonicalize("&#x3c").should == "<"
        encoder.canonicalize("&#x03c").should == "<"
        encoder.canonicalize("&#x0003c").should == "<"
        encoder.canonicalize("&#x000003c").should == "<"
        encoder.canonicalize("&#x00000003c").should == "<"
        encoder.canonicalize("&#x3c;").should == "<"
        encoder.canonicalize("&#x03c;").should == "<"
        encoder.canonicalize("&#x003c;").should == "<"
        encoder.canonicalize("&#x00003c;").should == "<"
        encoder.canonicalize("&#x0000003c;").should == "<"
        encoder.canonicalize("&#X3c").should == "<"
        encoder.canonicalize("&#X03c").should == "<"
        encoder.canonicalize("&#X0003c").should == "<"
        encoder.canonicalize("&#X000003c").should == "<"
        encoder.canonicalize("&#X00000003c").should == "<"
        encoder.canonicalize("&#x3C").should == "<"
        encoder.canonicalize("&#x03C").should == "<"
        encoder.canonicalize("&#x0003C").should == "<"
        encoder.canonicalize("&#x000003C").should == "<"
        encoder.canonicalize("&#x00000003C").should == "<"
        encoder.canonicalize("&#X3C").should == "<"
        encoder.canonicalize("&#X03C").should == "<"
        encoder.canonicalize("&#X0003C").should == "<"
        encoder.canonicalize("&#X000003C").should == "<"
        encoder.canonicalize("&#X00000003C").should == "<"
        encoder.canonicalize("&lt").should == "<"
        encoder.canonicalize("&LT").should == "<"
        encoder.canonicalize("&Lt").should == "<"
        encoder.canonicalize("&lT").should == "<"
        encoder.canonicalize("&lt;").should == "<"
        encoder.canonicalize("&LT;").should == "<"
        encoder.canonicalize("&Lt;").should == "<"
        encoder.canonicalize("&lT;").should == "<"
        encoder.canonicalize("&#37;").should == "%"
        encoder.canonicalize("&#37").should == "%"
        encoder.canonicalize("&#37b").should == "%b"
        encoder.canonicalize("%3Cscript%3Ealert%28%22hello%22%29%3B%3C%2Fscript%3E") == "<script>alert(\"hello\");</script>"
        begin
          encoder.canonicalize("%3Cscript&#x3E;alert%28%22hello&#34%29%3B%3C%2Fscript%3E") == "<script>alert(\"hello\");</script>"
        rescue IntrustionException => e
          puts e.log_message
        end
        pending("Add JS, Percentage")
      end
      # Canocialize
      it "should canonicalize input" do
        pending "Add test once other codecs in place"
      end
      # Double canonicalize
      it "should canonicalize double encoded inputs and send warnings" do

        encoder.sanitize("&#x26;lt&#59",false).should == "<" # double entity
        encoder.sanitize("%255c",false).should == "\\" # double percent
        encoder.sanitize("%2525",false).should == "%" #double percent
        encoder.sanitize("%26lt%3b",false).should == "<" #double percent
        # multi scheme double encoding
        encoder.sanitize("%26lt%3b",false).should == "<"
        encoder.sanitize("&#x25;26",false).should == "&"
        # nested encoding
        encoder.sanitize("%253c", false).should == "<"
        encoder.sanitize("%%33%63", false).should == "<"
        encoder.sanitize("%%33c", false).should == "<"
        encoder.sanitize("%3%63", false).should == "<"
        encoder.sanitize("&&#108;t;", false).should == "<"
        encoder.sanitize("&%6ct;", false).should == "<"
        encoder.sanitize("%&#x33;c", false).should == "<"
        # multi encoding test
        encoder.sanitize("%25 %2526 %26#X3c;script&#x3e; &#37;3Cscript%25252525253e", false).should == "% & <script> <script>"
        encoder.sanitize("%26lt; %26lt; &#X25;3c &#x25;3c %2526lt%253B %2526lt%253B %2526lt%253B", false).should == "< < < < < < <"
        # strict mode
        begin
          encoder.sanitize("%26lt; %26lt; &#X25;3c &#x25;3c %2526lt%253B %2526lt%253B %2526lt%253B", true).should == "< < < < < < <"
        rescue IntrustionException => e
          # expect a warning
          e.message.should == "Input validation failure"
        end

        begin
          encoder.sanitize("%253Cscript",true).should == "<script"
         rescue IntrustionException => e
            # expect a warning
            e.message.should == "Input validation failure"
          end

        begin
          encoder.sanitize("&#37;3Cscript",true).should == "<script"
         rescue IntrustionException => e
            # expect a warning
            e.message.should == "Input validation failure"
          end
      end


      # Css Encoder
      it "should css encode nil as nil" do
        result = encoder.encode_for_css(nil)
        result.should == nil
      end

      it "should css encode <script> as '\\3cscript\\3e" do
        result = encoder.encode_for_css("<script>")
        result.should == "\\3c script\\3e "
      end

      it "should css encode punction properly" do
        result = encoder.encode_for_css("!@$%()=+{}[]")
        result.should == "\\21 \\40 \\24 \\25 \\28 \\29 \\3d \\2b \\7b \\7d \\5b \\5d "
      end

      # HTML Encoder


      # JS Encoder
      it "should js encode special characers" do
        pending("Add JS encoder")
      end
      it "should js encode ',.-_ '" do
        pending("Add JS encoder")
      end
      it "should js encode a script tag" do
        pending("Add JS encoder")
      end
    end
  end
end
