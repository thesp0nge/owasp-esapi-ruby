=begin
  Codec to provide for MySQL string support
  http://mirror.yandex.ru/mirrors/ftp.mysql.com/doc/refman/5.0/en/string-syntax.html for details

=end
module Owasp
  module Esapi
    module Codec
      class MySQLCodec < BaseCodec
        MODE_ANSI = 1
        MODE_MYSQL = 0;
=begin
  create a mysql codec.
  mode must be either MODE_MYSQL or MODE_ANSI
  The mode sets wether to use ANSI_QUOTES mode in mysql or not
  defaults tp MODE_MYSQL
=end
        def initialize(mode = 0)
          if mode < 0 or mode > 1
            raise RangeError.new()
          end
          @mode = mode
        end

=begin
  quote encode character
=end
        def encode_char(immune,input)
          return input if immune.include?(input)
          hex = hex(input)
          return input if hex.nil?
          return to_ansi(input) if @mode == MODE_ANSI
          return to_mysql(input) if @mode == MODE_MYSQL
        end

=begin
  decode a character using the mode
=end
        def decode_char(input)
          return from_ansi(input) if @mode == MODE_ANSI
          return from_mysql(input) if @mode == MODE_MYSQL
        end

        private
=begin
  encode ' only
=end
        def to_ansi(input)
          return "\'\'" if input == "\'"
          input
        end
=begin
  encode for NO_BACKLASH_MODE
=end
        def to_mysql(input)
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

=begin
  decode a char with ansi only compliane i.e. apostrohpe only
=end
        def from_ansi(input)
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

=begin
  decode a char using mysql NO_BACKSLAH_QUOTE rules
=end
        def from_mysql(input)
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
