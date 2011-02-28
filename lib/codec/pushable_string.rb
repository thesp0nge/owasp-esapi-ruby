# The pushback string is used by Codecs to allow them to push decoded characters back onto a string
# for further decoding. This is necessary to detect double-encoding.

module Owasp
  module Esapi
    module Codec
      class PushableString
        attr :index

        #
        # Setup a pushable string
        # stream will setup UTF_8 encoding on the input
        def initialize(string)
          @input = string.force_encoding(Encoding::UTF_8)
          @index = 0
          @mark = 0
          @temp = nil
          @push = nil
        end

        # Get the next token off of the stream
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
          t
        end

        #  fetch the next hex token in the string or nil
        def next_hex
          c = self.next
          return nil if c.nil?
          return c if hex?(c)
          nil
        end

        # Fetch the next octal token int eh string or nil
        def next_octal
          c = self.next
          return nil if c.nil?
          return c if octal?(c)
          nil
        end

        #  Check to see if we have another token on the stream
        def next?
          !@push.nil? ? true : @input.nil? ? false : @input.empty? ? false : @index >= @input.length ? false : true
        end

        #  Push a character back onto the string, this is a unread operation
        def push(c)
          @push = c
        end

        #  Peek into teh stream and see if the next character is the one in question
        def peek?(c)
          return true if !@push.nil? and @push == c
          return false if @input.empty?
          return false if @input.nil?
          return false if @index >= @input.size
          @input[@index] == c
        end

        #  Peek into the stream and fetch teh next character without moving the index
        def peek
          return @push if !@push.nil?
          return nil if @input.nil?
          return nil if @input.empty?
          return nil if @index >= @input.size
          @input[@index]
        end

        #  Mark the stream for rewind
        def mark
          @temp = @push
          @mark = @index
        end

        # Check if a given character is a hexadecimal character
        def hex?(c)
          return false if c.nil?
          c =~ /[a-fA-F0-9]/
        end

        #  Check if a given character is an octal character
        def octal?(c)
          return false if c.nil?
          c =~ /[0-7]/
        end

        #  Reset the index back to the mark
        def reset
          @push = @temp
          @index = @mark
        end

        #  Fetch the rest of the string from the current index
        def remainder
          t = @input.slice(@index,@input.size-@index)
          return @push + t unless @push.nil?
          t
        end
      end
    end
  end
end
