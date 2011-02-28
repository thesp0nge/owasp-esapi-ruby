require File.expand_path(File.dirname(__FILE__) + '../../spec_helper')

module Owasp
  module Esapi
    module Validator
      describe StringValidator do
        let(:rule) {Owasp::Esapi::Validator::StringValidator.new("test")}
        # We will reset teh rule before every test so previous white/blacklist entries dont affect the other
        # test begin executed
        before(:all) { @@rule = Owasp::Esapi::Validator::StringValidator.new("test")}

        describe "Pattern rules" do
          it "should fail to add a nil white list rule" do
            lambda { rule.add_whitelist(nil)}.should raise_error(ArgumentError)
          end

          it "should fail with an invalid regex" do
            lambda { rule.add_whitelist("_][0}[")}.should raise_error(RegexpError)
          end

          it "should fail to add a nil black list rule" do
            lambda { rule.add_blacklist(nil)}.should raise_error(ArgumentError)
          end

          it "should fail with an invalid regex" do
            lambda { rule.add_blacklist("_][0}[")}.should raise_error(RegexpError)
          end

          it "should reject beg<script>end with blacklist pattern ^.*(<|>).*" do
            beg = "beg <script> end"
            rule.valid("",beg).should == beg
            rule.add_blacklist("^.*(<|>).*")
            lambda { rule.valid("",beg)}.should raise_error(Owasp::Esapi::ValidationException)
            rule.valid("","beg script end").should == "beg script end"
          end

          it "should accept Magnum44 with whitelist ^[a-zA-Z]*" do
            gun = "Magnum44"
            rule.valid("",gun).should == gun
            rule.add_whitelist("^[a-zA-Z]*")
            lambda { rule.valid("",gun)}.should raise_error(Owasp::Esapi::ValidationException)
            rule.valid("","MagnumPI").should == "MagnumPI"
          end

          it "should match ^[A-Za-z0-9._%-]+@[A-Za-z0-9.-]+\\.[a-zA-Z]{2,4}$ with sal.scotto@gmail.com" do
            rule.add_whitelist("^[A-Za-z0-9._%-]+@[A-Za-z0-9.-]+\\.[a-zA-Z]{2,4}$")
            rule.valid?("Email test","sal.scotto@gmail.com").should be_true
          end

        end

        describe "Length rules" do
          [
            "12",
            "123456",
            "ABCDEFGHIJKL"
          ].each do |input|
            it "should check valid length for #{input} with min 2 max 12" do
              rule.min = 2
              rule.max = 12
              rule.valid?("",input).should be_true
            end
          end

          [
            "1",
            "ABCDEFGHIJKLM"
          ].each do |input|
            it "should check invalid lengths for #{input} with min2 max 12" do
              rule.min = 2
              rule.max = 12
              rule.valid?("",input).should be_false
            end
          end

          it "should add error for invalid lengths" do
            list =  Owasp::Esapi::Validator::ValidatorErrorList.new
            rule.min = 2
            rule.max = 12
            rule.validate("","1234567890",list)
            list.errors.should be_empty
            rule.validate("",nil,list)
            list.errors.should have_exactly(1).items
          end
        end

        describe "Null Rules" do
          it "should allow nil for valid? when set to allow_nil" do
            rule.allow_nil = true
            rule.valid?("",nil).should be_true
          end

          it "should not allow nil for valid? when allow_nil is false" do
            rule.valid?("",nil).should be_false
          end

        end


      end
    end
  end
end
