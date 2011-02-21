class OSDetect

  def self.os

  end
end
require 'rbconfig'
=begin
  Operating system codec for escape characters for HOST commands
  We look at Unix style (max, linux) and Windows style
=end
module Owasp
  module Esapi
    module Codec
      class OsCodec < BaseCodec
        WINDOWS_HOST = :Windows
        UNIX_HOST = :Unix
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

=begin
  get the host OS type
=end
        def os
          @host
        end

        def encode_char(immune,input)
          return input if immune.include?(input)
          return input if hex(input).nil?
          return "#{@escape_char}#{input}"
        end

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