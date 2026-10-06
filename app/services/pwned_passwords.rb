require "net/http"

# Client for the Pwned Passwords range API of Have I Been Pwned (TASK-030).
# k-anonymity: only the first five hex characters of the password's SHA-1
# leave the hub; the API answers with every hash suffix it knows under that
# prefix and the comparison happens here. Padded responses (Add-Padding) keep
# the response size from hinting at the prefix. No API key is needed.
module PwnedPasswords
  RANGE_URL = "https://api.pwnedpasswords.com/range/".freeze
  # Seconds per connect and per read: someone is waiting on the form.
  TIMEOUT = 3

  # The API could not be asked, or did not answer with a range.
  class Unavailable < StandardError; end

  # @param password [String]
  # @return [Boolean] whether the password appears in a known breach
  # @raise [Unavailable]
  def self.breached?(password)
    digest = Digest::SHA1.hexdigest(password).upcase
    prefix = digest[0, 5]
    suffix = digest[5..]
    range(prefix).each_line.any? do |line|
      candidate, count = line.strip.split(":")
      # Padding entries carry a count of 0.
      candidate == suffix && count.to_i.positive?
    end
  end

  def self.range(prefix)
    uri = URI("#{RANGE_URL}#{prefix}")
    response = Net::HTTP.start(uri.host, uri.port, use_ssl: true, open_timeout: TIMEOUT, read_timeout: TIMEOUT,
                                                   ssl_timeout: TIMEOUT) do |http|
      http.get(uri.request_uri, "Add-Padding" => "true", "User-Agent" => "SecureSSOHub")
    end
    raise Unavailable, "HTTP #{response.code}" unless response.is_a?(Net::HTTPSuccess)

    response.body.to_s
  rescue Timeout::Error, SocketError, SystemCallError, IOError, OpenSSL::SSL::SSLError,
         Net::HTTPBadResponse, Net::ProtocolError => e
    raise Unavailable, "#{e.class}: #{e.message}"
  end
  private_class_method :range
end
