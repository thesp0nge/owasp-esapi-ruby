require 'rbconfig'

# Operating system codec for escape characters for HOST commands
# We look at Unix style (max, linux) and Windows style
module Owasp
  module Esapi
    module Codec
      class OsCodec < BaseCodec
        # Window Host flag
        WINDOWS_HOST = :Windows
        # Unix Host flag
        UNIX_HOST = :Unix

        # Setup the code, if no os is passed in the codec
        # will guess the OS based on the ruby host_os variable
        def initialize(os = nil)
          @host = nil
          @escape_char = ''
          host_os = os
          if os.nil?
            host_os = case Config::CONFIG['host_os']
            when /mswin|windows/i then WINDOWS_HOST
            when /linux/i then UNIX_HOST
            when /darwin/i then UNIX_HOST
            when /sunos|solaris/i then UNIX_HOST
            else UNIX_HOST
            end
          end
          if host_os == WINDOWS_HOST
            @host = WINDOWS_HOST
            @escape_char = '^'
          elsif host_os == UNIX_HOST
            @host = UNIX_HOST
            @escape_char = '\\'
          end
        end

        # get the configured OS
        def os
          @host
        end

        # Returns shell encoded character
        # ^ - for windows
        # \\ - for unix
        def encode_char(immune,input)
          return input if immune.include?(input)
          return input if hex(input).nil?
          return "#{@escape_char}#{input}"
        end

        # Returns the decoded version of the character starting at index, or
        # nil if no decoding is possible.
        # <p>
        # Formats all are legal both upper/lower case:
        #   ^x - all special characters when configured for WINDOWS
        #   \\ - all special characters when configured for UNIX
        def decode_char(input)
          input.mark
          first = input.next
          # check first char
          if first.nil?
            input.reset
            return nil
          end
          # if it isnt escape return nil
          if first != @escape_char
            input.reset
            return nil
          end
          # get teh escape value
          return input.next
        end

      end
    end
  end
end
