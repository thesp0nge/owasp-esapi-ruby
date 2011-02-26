#
# Codec to provide for MySQL string support
# http://mirror.yandex.ru/mirrors/ftp.mysql.com/doc/refman/5.0/en/string-syntax.html for details
module Owasp
  module Esapi
    module Codec
      class MySQLCodec < BaseCodec
        MYSQL_MODE = 0 # MySQL standard mode
        ANSI_MODE  = 1; # ANSI escape mode

        #  create a mysql codec.
        # mode must be either MYSQL_MODE or ANSI_MODE
        # The mode sets wether to use ansi mode in mysql or not
        # defaults to MYSQL_MODE
        def initialize(mode = 0)
          if mode < MYSQL_MODE or mode > ANSI_MODE
            raise RangeError.new()
          end
          @mode = mode
        end

        #  Returns quote-encoded *character*
        def encode_char(immune,input)
          return input if immune.include?(input)
          hex = hex(input)
          return input if hex.nil?
          return to_ansi(input) if @mode == ANSI_MODE
          return to_mysql(input) if @mode == MYSQL_MODE
        end

        # Returns the decoded version of the character starting at index, or
        # nil if no decoding is possible.
        #
        # Formats all are legal (case sensitive)
        #   In ANSI_MODE '' decodes to '
        #   In MYSQL_MODE \x decodes to x (or a small list of specials)
        def decode_char(input)
          return from_ansi(input) if @mode == ANSI_MODE
          return from_mysql(input) if @mode == MYSQL_MODE
        end

        #  encode ' only
        def to_ansi(input) #:nodoc:
          return "\'\'" if input == "\'"
          input
        end

        #  encode for NO_BACKLASH_MODE
        def to_mysql(input) # :nodoc:
          c = input.ord
          return "\\0" if c == 0x00
          return "\\b" if c == 0x08
          return "\\t" if c == 0x09
          return "\\n" if c == 0x0a
          return "\\r" if c == 0x0d
          return "\\Z" if c == 0x1a
          return "\\\"" if c == 0x22
          return "\\%" if c == 0x25
          return "\\'" if c == 0x27
          return "\\\\" if c == 0x5c
          return "\\_" if c == 0x5f
          "\\#{input}"
        end

        #  decode a char with ansi only compliane i.e. apostrohpe only
        def from_ansi(input) # :nodoc:
          input.mark
          first = input.next

          # check first char
          if first.nil?
            input.reset
            return nil
          end

          unless first == "\'"
            input.reset
            return nil
          end

          # check second char
          second = input.next
          if second.nil?
            input.reset
            return nil
          end

          # if second isnt an encoded char return nil
          unless second == "\'"
            input.reset
            return nil
          end
          "\'"
        end

        #  decode a char using mysql NO_BACKSLAH_QUOTE rules
        def from_mysql(input) # :nodoc:
          input.mark
          # check first
          first = input.next
          if first.nil?
            input.reset
            return nil
          end

          # check second
          second = input.next
          if second.nil?
            input.reset
            return nil
          end

          return 0x00.chr if second == "0"
          return 0x08.chr if second == "b"
          return 0x08.chr if second == "t"
          return 0x0a.chr if second == "n"
          return 0x0d.chr if second == "r"
          return 0x1a.chr if second == "z"
          return 0x22.chr if second == "\""
          return 0x25.chr if second == "%"
          return 0x27.chr if second == "\'"
          return 0x5c.chr if second == "\\"
          return 0x5f.chr if second == "_"
          # not an escape
          second
        end

      end
    end
  end
end
