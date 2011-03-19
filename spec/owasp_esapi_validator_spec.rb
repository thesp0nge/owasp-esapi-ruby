module Owasp
  module Esapi
    describe Validator do
      let(:validator) { Owasp::Esapi::Validator}
      let(:allow_null) { false }

      before do
        # Global HTTP Validation Rules
        # Values with Base64 encoded data (e.g. encrypted state) will need at least [a-zA-Z0-9\/+=]
        {
          "AccountName"=>"^[a-zA-Z0-9]{3,20}$",
          "SystemCommand"=>"^[a-zA-Z\\-\\/]{1,64}$",
          "RoleName"=>"^[a-z]{1,20}$",
          "HTTPScheme"=>"^(http|https)$",
          "HTTPServerName"=>"^[a-zA-Z0-9_.\\-]*$",
          "HTTPParameterName"=>"^[a-zA-Z0-9_]{1,32}$",
          "HTTPParameterValue"=>"^[a-zA-Z0-9.\\-\\/+=_ ]*$",
          "HTTPCookieName"=>"^[a-zA-Z0-9\\-_]{1,32}$",
          "HTTPCookieValue"=>"^[a-zA-Z0-9\\-\\/+=_ ]*$",
          "HTTPHeaderName"=>"^[a-zA-Z0-9\\-_]{1,32}$",
          "HTTPHeaderValue"=>"^[a-zA-Z0-9()\\-=\\*\\.\\?;,+\\/:&_ ]*$",
          "HTTPContextPath"=>"^[a-zA-Z0-9.\\-\\/_]*$",
          "HTTPServletPath"=>"^[a-zA-Z0-9.\\-\\/_]*$",
          "HTTPPath"=>"^[a-zA-Z0-9.\\-_]*$",
          "HTTPQueryString"=>"^[a-zA-Z0-9()\\-=\\*\\.\\?;,+\\/:&_ %]*$",
          "HTTPURI"=>"^[a-zA-Z0-9()\\-=\\*\\.\\?;,+\\/:&_ ]*$",
          "HTTPURL"=>"^.*$",
          "HTTPJSESSIONID"=>"^[A-Z0-9]{10,30}$",
          "FileName"=>'^[a-zA-Z0-9!@#$%^&{}\[\]()_+\-=,.~\'` ]{1,255}$',
          "DirectoryName"=>'^[a-zA-Z0-9:/\\\\!@#$%^&{}\[\]()_+\-=,.~\'` ]{1,255}$',
          "SafeString"=>%w{^[.\\p{Alnum}\\p{Space}]{0,1024}$},
          "Email"=>"^[A-Za-z0-9._%\-]+@[A-Za-z0-9.\-]+\\.[a-zA-Z]{2,4}$",
          "IPAddress"=>/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/,
          "URL"=>/^(ht|f)tp(s?)\:\/\/[0-9a-zA-Z]([-.\w]*[0-9a-zA-Z])*(:(0-9)*)*(\/?)([a-zA-Z0-9\-\.\?\,\:\'\/\\\\+=&amp;%\$#_]*)?$/,
          "CreditCard"=>/^(\d{4}[- ]?){3}\d{4}$/,
          "SSN"=>/^(?!000)([0-6]\d{2}|7([0-6]\d|7[012]))([ -]?)(?!00)\d\d\3(?!0000)\d{4}$/,
          "USZipCode" => "^\\d{5}(\\-\\d{4})?$",
          "ItalianZipCode" => "^\\d{5}$",
        }.each_pair do |name,expression|
          Owasp::Esapi.security_config.add_pattern(name,expression)
        end
      end
      describe "-StringTests-" do
        it "should return true for a nil" do
          validator.valid_string?("test",nil,"Email",100,true,true).should be_true
        end
        # test cases that should pass
        {
         "jeff.williams@aspectsecurity.com" => "Email",
         "123.168.100.234" => "IPAddress",
         "192.168.1.234" => "IPAddress",
          "http://www.aspectsecurity.com"=> "URL",
          "078-05-1120"=> "SSN",
          "078 05 1120"=> "SSN",
          "078051120"=> "SSN",
          "c:\\ridiculous" => "DirectoryName",
          "c:\\temp\\..\\etc" => "DirectoryName",
          "/bin/sh" => 'DirectoryName',
          "1234987600000008" => "CreditCard",
        }.each_pair do |input,rule|
          it "should test #{rule} against #{input} as valid" do
            validator.valid_string?("test",input,rule,100,true,true).should be_true
          end
        end
        # test cases that should fail
        {
          "jeff.williams@@aspectsecurity.com" => "Email",
          "jeff.williams@aspectsecurity" => "Email",
          "..168.1.234"=> "IPAddress",
          "10.x.1.234"=> "IPAddress",
          "http:///www.aspectsecurity.com" => "URL",
           "http://www.aspect security.com"=> "URL",
           "987-65-4320"=> "SSN",
           "000-00-0000"=> "SSN",
           "(555) 555-5555"=> "SSN",
           "test"=> "SSN",
           "4417 1234 5678 911Z" => "CreditCard",
           "C:test" => "DirectoryPath",
        }.each_pair do |input,rule|
          it "should test #{rule} against #{input} as invalid" do
            validator.valid_string?("test",input,rule,100,false).should be_false
          end
        end

      end

    end
  end
end
