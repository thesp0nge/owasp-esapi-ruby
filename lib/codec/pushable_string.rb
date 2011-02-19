#
# This code is a direct port of the OWASP ESAPI API
#
# Original Author: Jeff Williams
# Port Author: Sal ScottoDiLuzio
#

module Owasp
  module Esapi
    module Codec
      class PushableString
        attr :index
        def initialize(string)
          @string = string
          @index = 0
          @mark = 0
          @temp = nil
          @push = nil
        end
        def next
          unless @push.nil?
            t = @push
            @push = nil
            return t
          end
          if @string.nil?
            return nil
          end
          if @string.size == 0
            return nil
          end
          if @index >= @string.size
            return nil
          end
          t = @string[@index]
          @index += 1
          return t
        end

        def next?
          !@push.nil? ? true : @string.nil? ? false : @string.empty? ? false : @index >= @string.length ? false : true
        end

        def push(c)
          @push = c
        end

        def peek?(c)
          if ! @push.nil? and @push == c
            return true
          end
          if @string.empty?
            return false
          end
          if @string.nil?
            return false
          end
          if @index >= @string.size
            return false
          end
          return @string[@index] == c

        end

        def peek
          if !@push.nil?
            return @push
          end
          if @string.nil?
            return nil
          end
          if @string.empty?
            return nil
          end
          if @index >= @string.size
            return nil
          end
          return @string[@index]
        end

        def mark
          @temp = @push
          @mark = @index
        end

        def is_hex(c)
          if c.nil?
            return false
          end
          c =~ /[a-fA-F0-9]/
        end

        def reset
          @push = @temp
          @index = @mark
        end

        def remainder
          t = @string.slice(@index,@stirng.size-@index)
          unless @push.nil?
            return @push + t
          end
          return t
        end
      end
    end
  end
end

