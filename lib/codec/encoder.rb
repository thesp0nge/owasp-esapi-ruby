module Owasp
  module Esapi
    class Encoder
      # Immune character data
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
      @@codecs = []
      @@html_codec = Owasp::Esapi::Codec::HtmlCodec.new
      @@xml_codec = nil
      @@percent_codec = Owasp::Esapi::Codec::PercentCodec.new
      @@js_codec = nil
      @@vb_codec = nil
      @@css_codec = Owasp::Esapi::Codec::CssCodec.new

      # Create an encoder, optionally pass in a list of codecs to use
      def initialize(configured_codecs = nil)
        unless configured_codecs.nil?
          configured_codes.each do |codec|
            @@codecs << codec
          end
        else
          # setup some defaults codecs
          @@codecs << @@css_codec
          @@codecs << @@html_codec
          @@codecs << @@percent_codec
        end
      end
=begin
  canonicalize(input)
  input will be tested and canonicalize
  if security configuration is set for intrustion detection
  we will raise an exception on mix encodings
=end
      def canonicalize(input)
        # if the input is nil, just return nil
        return nil if input.nil?

        # check teh ESAPI config and figure out if we want strict encoding
        return sanitize(input,Owasp::Esapi.security_config.ids?)
      end
=begin
  sanitize(input,strict)
  input i the data to test
  strict indicates if we will throw an intrustionexception when mixed-encoding is found
=end
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
          @@codecs.each do |codec|
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
        return working
      end
      # Some convience methods to access codecs without have to have create one

=begin
  encode_for_css(input)
  input is the data you wish to encode for CSS usage
=end
      def encode_for_css(input)
        return nil if input.nil?
        @@css_codec.encode(IMMUNE_CSS,input)
      end

      def encode_for_html(input)
        return nil if input.nil?
        @@html_codec.encode(IMMUNE_HTML,input)
      end
      def dencode_for_html(input)
        return nil if input.nil?
        @@html_codec.decode(input)
      end
      def encode_for_html_attr(input)
        return nil if input.nil?
        @@html_codec.encode(IMMUNE_HTMLATTR,input)
      end

    end
  end
end