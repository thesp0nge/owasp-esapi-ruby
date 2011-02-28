# The Encoder interface contains a number of methods for decoding input and encoding output
# so that it will be safe for a variety of interpreters. To prevent
# double-encoding, callers should make sure input does not already contain encoded characters
# by calling canonicalize. Validator implementations should call canonicalize on user input
# <b>before</b> validating to prevent encoded attacks.
# All of the methods must use a "whitelist" or "positive" security model.
# For the encoding methods, this means that all characters should be encoded, except for a specific list of
# "immune" characters that are known to be safe.
# The Encoder performs two key functions, encoding and decoding. These functions rely
# on a set of codecs that can be found in the org.owasp.esapi.codecs package. These include:
# * CSS Escaping<
# * HTMLEntity Encoding
# * JavaScript Escaping
# * MySQL Escaping
# * Oracle Escaping
# * Percent Encoding (aka URL Encoding)
# * Unix Escaping
# * VBScript Escaping
# * Windows Encoding

require 'cgi'
require 'base64'
require 'codec/base_codec'
require 'codec/pushable_string'
require 'codec/base_codec'
require 'codec/css_codec'
require 'codec/html_codec'
require 'codec/percent_codec'
require 'codec/javascript_codec'
require 'codec/os_codec'
require 'codec/vbscript_codec'
require 'codec/oracle_codec'
require 'codec/mysql_codec'
require 'codec/xml_codec'

module Owasp
  module Esapi
    class Encoder
      #
      # == Immune Character feilds
      #
      IMMUNE_CSS        = [ ]
      IMMUNE_HTMLATTR   = [ ',', '.', '-', '_' ]
      IMMUNE_HTML       = [ ',', '.', '-', '_', ' ' ]
      IMMUNE_JAVASCRIPT = [ ',', '.', '_' ]
      IMMUNE_VBSCRIPT   = [ ',', '.', '_' ]
      IMMUNE_XML        = [ ',', '.', '-', '_', ' ' ]
      IMMUNE_SQL        = [ ' ' ]
      IMMUNE_OS         = [ '-' ]
      IMMUNE_XMLATTR    = [ ',', '.', '-', '_' ]
      IMMUNE_XPATH      = [ ',', '.', '-', '_', ' ' ]
      PASSWORD_SPECIALS = "!$*-.=?@_"
      # == Standard Characetr Sets
      CHAR_LCASE = "abcdefghijklmnopqrstuvwxyz"
      CHAR_UCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
      CHAR_DIGITS = "0123456789"
      CHAR_SPECIALS = "!$*+-.=?@^_|~"
      CHAR_LETTERS = "#{CHAR_LCASE}#{CHAR_UCASE}"
      CHAR_ALPHANUMERIC = "#{CHAR_LETTERS}#{CHAR_DIGITS}"

      # Create the encoder, optionally pass in a list of codecs to use
      def initialize(configured_codecs = nil)
        # codec list
        @codecs = []
        # default codecs
        @html_codec = Owasp::Esapi::Codec::HtmlCodec.new
        @percent_codec = Owasp::Esapi::Codec::PercentCodec.new
        @js_codec = Owasp::Esapi::Codec::JavascriptCodec.new
        @vb_codec = Owasp::Esapi::Codec::VbScriptCodec.new
        @css_codec = Owasp::Esapi::Codec::CssCodec.new
        @xml_codec = Owasp::Esapi::Codec::XmlCodec.new
        unless configured_codecs.nil?
          configured_codecs.each do |c|
            @codecs << c
          end
        else
          # setup some defaults codecs
          @codecs << @html_codec
          @codecs << @percent_codec
          @codecs << @js_codec
        end
      end

      # This method is equivalent to calling sanitize(input, true)
      def canonicalize(input)
        # if the input is nil, just return nil
        return nil if input.nil?

        # check teh ESAPI config and figure out if we want strict encoding
        sanitize(input,Owasp::Esapi.security_config.ids?)
      end

      # Sanitization is simply the operation of reducing a possibly encoded
      # string down to its simplest form. This is important, because attackers
      # frequently use encoding to change their input in a way that will bypass
      # validation filters, but still be interpreted properly by the target of
      # the attack. Note that data encoded more than once is not something that a
      # normal user would generate and should be regarded as an attack.
      # Everyone says[http://cwe.mitre.org/data/definitions/180.html] you shouldn't do validation
      # without canonicalizing the data first. This is easier said than done. The canonicalize method can
      # be used to simplify just about any input down to its most basic form. Note that sanitization doesn't
      # handle Unicode issues, it focuses on higher level encoding and escaping schemes. In addition to simple
      # decoding, sanitize also handles:
      # * Perverse but legal variants of escaping schemes
      # * Multiple escaping (%2526 or &#x26;lt;)
      # * Mixed escaping (%26lt;)
      # * Nested escaping (%%316 or &%6ct;)
      # * All combinations of multiple, mixed, and nested encoding/escaping (%2&#x35;3c or &#x2526gt;)
      #
      # Although ESAPI is able to canonicalize multiple, mixed, or nested encoding, it's safer to not accept
      # this stuff in the first place. In ESAPI, the default is "strict" mode that throws an IntrusionException
      # if it receives anything not single-encoded with a single scheme. Even if you disable "strict" mode,
      # you'll still get warning messages in the log about each multiple encoding and mixed encoding received.
      #
      def sanitize(input, strict)
        # check input again, as someone may just wana call sanitize
        return nil if input.nil?
        working = input
        found_codec = nil
        mixed_count = 1
        found_count = 0
        clean = false
        while !clean
          clean = true
          @codecs.each do |codec|
            old = working
            working = codec.decode(working)
            if !old.eql?(working)
              if !found_codec.nil? and found_codec != codec
                mixed_count += 1
              end
              found_codec = codec
              if clean
                found_count += 1
              end
              clean = false
            end
          end
        end
        # test for strict encoding, and indicate mixed and multiple errors
        if found_count >= 2 and mixed_count > 1
          if strict
            raise Owasp::Esapi::IntrustionException.new("Input validation failure", "Multiple (#{found_count}x) and mixed encoding (#{mixed_count}x) detected in #{input}")
          else
            Owasp::Esapi.logger.warn("Multiple (#{found_count}x) and mixed encoding (#{mixed_count}x) detected in #{input}")
          end
        elsif found_count >= 2
          if strict
            raise Owasp::Esapi::IntrustionException.new("Input validation failure", "Multiple (#{found_count}x) detected in #{input}")
          else
            Owasp::Esapi.logger.warn("Multiple (#{found_count}x) detected in #{input}")
          end
        elsif mixed_count > 1
          if strict
            raise Owasp::Esapi::IntrustionException.new("Input validation failure", "Mixed encoding (#{mixed_count}x) detected in #{input}")
          else
            Owasp::Esapi.logger.warn("Mixed encoding (#{mixed_count}x) detected in #{input}")
          end
        end
        working
      end

      # Encode for Base64. using the url safe input set
      def encode_for_base64(input)
        return nil if input.nil?
        Base64.urlsafe_encode64(input)
      end

      # Decode data encoded with BASE-64 encoding.
      # it assumes url safe encoding sets
      def decode_for_base64(input)
        return nil if input.nil?
        Base64.urlsafe_decode64(input)
      end

      def encode_for_ldap(input)
      end
      def encode_for_dn(input)
      end

      # Encode for use in a URL. This method performs URL encoding[http://en.wikipedia.org/wiki/Percent-encoding]
      # on the entire string.
      def encode_for_url(input)
        return nil if input.nil?
        CGI::escape(input)
      end

      # Decode from URL. First canonicalize and detect any double-encoding.
      # If this check passes, then the data is decoded using URL decoding.
      def decode_for_url(input)
        return nil if input.nil?
        clean = sanitize(input)
        CGI::unescape(input,Owasp::Esapi.security_config.encoding)
      end

      # Encode data for use in Cascading Style Sheets (CSS) content.
      # CSS Syntax[http://www.w3.org/TR/CSS21/syndata.html#escaped-characters] (w3.org)
      def encode_for_css(input)
        return nil if input.nil?
        @css_codec.encode(IMMUNE_CSS,input)
      end

      # Encode data for insertion inside a data value or function argument in JavaScript. Including user data
      # directly inside a script is quite dangerous. Great care must be taken to prevent including user data
      # directly into script code itself, as no amount of encoding will prevent attacks there.
      #
      # Please note there are some JavaScript functions that can never safely receive untrusted data
      # as input – even if the user input is encoded.
      #
      # For example:
      #
      #  <script>
      #  window.setInterval('<%= EVEN IF YOU ENCODE UNTRUSTED DATA YOU ARE XSSED HERE %>');
      #  </script>
      #
      def encode_for_javascript(input)
        return nil if input.nil?
        @js_codec.encode(IMMUNE_JAVASCRIPT,input)
      end

      # Encode data for use in HTML using HTML entity encoding
      # <p>
      # Note that the following characters:
      # 00-08, 0B-0C, 0E-1F, and 7F-9F
      # cannot be used in HTML.
      #
      # * HTML Encodings[http://en.wikipedia.org/wiki/Character_encodings_in_HTML] (wikipedia.org)
      # * SGML Specification[http://www.w3.org/TR/html4/sgml/sgmldecl.html] (w3.org)
      # * XML Specification[http://www.w3.org/TR/REC-xml/#charsets] (w3.org)
      def encode_for_html(input)
        return nil if input.nil?
        @html_codec.encode(IMMUNE_HTML,input)
      end

      # Decodes HTML entities.
      def dencode_for_html(input)
        return nil if input.nil?
        @html_codec.decode(input)
      end

      #  Encode data for use in HTML attributes.
      def encode_for_html_attr(input)
        return nil if input.nil?
        @html_codec.encode(IMMUNE_HTMLATTR,input)
      end

      # Encode for an operating system command shell according to the configured OS codec
      #
      # Please note the following recommendations before choosing to use this method:
      #
      # 1. It is strongly recommended that applications avoid making direct OS system calls if possible as such calls are not portable, and they are potentially unsafe. Please use language provided features if at all possible, rather than native OS calls to implement the desired feature.
      # 2. If an OS call cannot be avoided, then it is recommended that the program to be invoked be invoked directly (e.g., Kernel.system("nameofcommand","parameterstocommand")) as this avoids the use of the command shell. The "parameterstocommand" should of course be validated before passing them to the OS command.
      # 3. If you must use this method, then we recommend validating all user supplied input passed to the command shell as well, in addition to using this method in order to make the command shell invocation safe.
      #
      # An example use of this method would be: Kernel.system("dir" ,encode_for_os(WindowsCodec, "parameter(s)tocommandwithuserinput");
      def encode_for_os(codec,input)
        return nil if input.nil?
        codec.encode(IMMUNE_OS,input)
      end

      # Encode data for insertion inside a data value in a Visual Basic script. Putting user data directly
      # inside a script is quite dangerous. Great care must be taken to prevent putting user data
      # directly into script code itself, as no amount of encoding will prevent attacks there.
      #
      # This method is not recommended as VBScript is only supported by Internet Explorer
      def encode_for_vbscript(input)
        return nil if input.nil?
        @vb_codec.encode(IMMUNE_VBSCRIPT,input)
      end

      # Encode input for use in a SQL query, according to the selected codec
      # (appropriate codecs include the MySQLCodec and OracleCodec).
      #
      # This method is not recommended. The use of the PreparedStatement
      # interface is the preferred approach. However, if for some reason
      # this is impossible, then this method is provided as a weaker
      # alternative.
      #
      # The best approach is to make sure any single-quotes are double-quoted.
      def encode_for_sql(codec,input)
        return nil if input.nil?
        codec.encode(IMMUNE_SQL,input)
      end

      # Encode data for use in an XPath query.
      #
      # NB: The reference implementation encodes almost everything and may over-encode.
      #
      # The difficulty with XPath encoding is that XPath has no built in mechanism for escaping
      # characters. It is possible to use XQuery in a parameterized way to
      # prevent injection.
      #
      # For more information, refer to this article[http://www.ibm.com/developerworks/xml/library/x-xpathinjection.html]
      # which specifies the following list of characters as the most dangerous: ^&"*';<>().
      #
      # This[http://www.packetstormsecurity.org/papers/bypass/Blind_XPath_Injection_20040518.pdf] paper suggests disallowing ' and " in queries.<p>
      # * XPath Injection[http://www.ibm.com/developerworks/xml/library/x-xpathinjection.html] (ibm.com)
      # * Blind XPath Injection[http://www.packetstormsecurity.org/papers/bypass/Blind_XPath_Injection_20040518.pdf] (packetstormsecurity.org)
      def encode_for_xpath(input)
        return nil if input.nil?
        @xml_codec.encode(IMMUNE_XPATH,input)
      end

      # Encode data for use in an XML element. The implementation should follow the
      # XML Encoding Standard[http://www.w3schools.com/xml/xml_encoding.asp] from the W3C.
      # <p>
      # The use of a real XML parser is strongly encouraged. However, in the
      # hopefully rare case that you need to make sure that data is safe for
      # inclusion in an XML document and cannot use a parse, this method provides
      # a safe mechanism to do so.
      def encode_for_xml(input)
        return nil if input.nil?
        @xml_codec.encode(IMMUNE_XML,input)
      end

      # Encode data for use in an XML attribute. The implementation should follow
      # the XML Encoding Standard[http://www.w3schools.com/xml/xml_encoding.asp] from the W3C.
      # <p>
      # The use of a real XML parser is highly encouraged. However, in the
      # hopefully rare case that you need to make sure that data is safe for
      # inclusion in an XML document and cannot use a parse, this method provides
      # a safe mechanism to do so.
      def encode_for_xml_attr(input)
        return nil if input.nil?
        @xml_codec.encode(IMMUNE_XMLATTR,input)
      end

    end
  end
end
