module Owasp
  module Esapi
    # FileScanner
    # This is class is unique to Esapi for Ruby
    # Users should developer thier own scanner class and configure esapi with the implmentation
    # The purpose of this class is to scan a file for encoding/viruses/etc
    # child classes only need to implment the scan method of the class
    class FileScanner
      # scan an IO object for viruses, encoding requirements, etc..
      # raise an Exception if there are any issues found within the IO stream
      # callers will be expected to rewind the stream
      def scan(io_object)
      end
    end
  end
end