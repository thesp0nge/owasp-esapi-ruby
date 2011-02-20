#
# A string we can peek and push
#

module Owasp
  module Esapi
    module Codec
      class PushableString
        attr :index
=begin
  Setup a pushable string
  stream will setup UTF_8 encoding on the input
=end
        def initialize(string)
          @input = string.force_encoding(Encoding::UTF_8)
          @index = 0
          @mark = 0
          @temp = nil
          @push = nil
        end
=begin
  Get the next token off of the stream
=end
        def next
          unless @push.nil?
            t = @push
            @push = nil
            return t
          end
          return nil if @input.nil?
          return nil if @input.size == 0
          return nil if @index >= @input.size

          t = @input[@index]
          @index += 1
          return t
        end
=begin
  get the next hex token in the string or nil
=end
        def next_hex
          c = self.next
          return nil if c.nil?
          return c if is_hex(c)
          return nil
        end
=begin
  get the next octal token int eh string or nil
=end
        def next_octal
          c = self.next
          return nil if c.nil?
          return c if is_octal(c)
          return nil
        end
=begin
  Check to see if we have another token on the stream
=end
        def next?
          !@push.nil? ? true : @input.nil? ? false : @input.empty? ? false : @index >= @input.length ? false : true
        end
=begin
  push a character back onto the string, this is an unread
=end
        def push(c)
          @push = c
        end
=begin
  Peek into teh stream and see if the next character is the one in question
=end
        def peek?(c)
          return true if ! @push.nil? and @push == c
          return false if @input.empty?
          return false if @input.nil?
          return false if @index >= @input.size
          return @input[@index] == c
        end
=begin
  Peek into the stream and fetch teh next character without moving the index
=end
        def peek
          return @push if !@push.nil?
          return nil if @input.nil?
          return nil if @input.empty?
          return nil if @index >= @input.size
          return @input[@index]
        end
=begin
  mark the stream for rewind
=end
        def mark
          @temp = @push
          @mark = @index
        end
=begin
  check if a given character is a hexadecimal character
  meaning a through f and 0 through 9
=end
        def is_hex(c)
          return false if c.nil?
          c =~ /[a-fA-F0-9]/
        end
=begin
  check if a given character is an octal character
  means 0 through 7
=end
        def is_octal(c)
          return false if c.nil?
          c =~ /[0-7]/
        end
=begin
  reset the index back to the mark
=end
        def reset
          @push = @temp
          @index = @mark
        end
=begin
  fetch the rest of the string from the current index
=end
        def remainder
          t = @input.slice(@index,@input.size-@index)
          return @push + t unless @push.nil?
          return t
        end
      end
    end
  end
end

