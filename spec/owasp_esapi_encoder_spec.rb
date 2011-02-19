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
         pending("Add other tests once the other codecs are ready")
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