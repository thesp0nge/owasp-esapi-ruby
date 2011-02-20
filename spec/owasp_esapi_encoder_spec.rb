require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

module Owasp
  module Esapi
    describe Encoder do
      let (:encoder) { Owasp::Esapi::Encoder.new }

      # Sanitize
      it "should sanitize input" do
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
        encoder.canonicalize("%3Cscript&#x3E;alert%28%22hello&#34%29%3B%3C%2Fscript%3E") == "<script>alert(\"hello\");</script>"
        pending("Add JS, Percentage")
      end
      # Canocialize
      it "should canonicalize input" do
        pending "Add test once other codecs in place"
      end
      # Double canonicalize
      it "should canonicalize double encoded inputs" do
        pending("Add once other codecs in place")
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
