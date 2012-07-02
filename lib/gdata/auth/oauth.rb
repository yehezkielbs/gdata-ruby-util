require 'openssl'
require 'digest/sha1'
require 'cgi'

module GData
  module Auth
    class OAuth

      attr_accessor :oauth_token, :oauth_secret, :consumer_key, :consumer_secret
      attr_writer :use_body_hash

      def initialize(options)
        @oauth_token     = options[:oauth_token]
        @oauth_secret    = options[:oauth_secret]
        @consumer_key    = options[:consumer_key]
        @consumer_secret = options[:consumer_secret]
        @use_body_hash   = options[:use_body_hash]
      end

      def sign_request!(request)
        header_parts = oauth_parameters(request)
        header_parts['oauth_signature'] = calc_signature(request, header_parts)
        request.headers['Authorization'] = "OAuth " + header_parts.map { |k,v| "#{k}=\"#{v}\"" }.sort.join(', ')
      end

      def use_body_hash?
        !!@use_body_hash
      end

      private

      def calc_signature(request, header_parts)
        signature = OpenSSL::HMAC::digest(OpenSSL::Digest::Digest.new('sha1'), sig_key, base_string(request, header_parts))
        signature = [signature].pack("m").chomp # base64 encode
        signature = CGI::escape(signature) # url encode
        signature
      end

      def sig_key
        # When using HMAC-SHA1, signature key is consumer_secret and
        # oauth_secret each encoded and separated with a '&'
        [consumer_secret, oauth_secret].map { |part| CGI::escape(part) }.join('&')
      end

      def base_string(request, header_parts)
        method = request.method.to_s.upcase
        norm_ps = normalize_parameters(request, header_parts)

        # Base string is method, base_url and normalized parameters,
        # each url encoded and separated with a '&'
        base_string = [method, base_url(request), norm_ps].map { |part| CGI::escape(part) }.join('&')
        base_string
      end

      def base_url(request)
        url = URI::parse(request.url)
        base_url = '%s://%s%s' % [url.scheme, url.host, url.path]
      end

      def need_body_hash?(request)
        return false unless use_body_hash?
        c_type = request.headers['Content-Type']
        is_form_urlencoded = c_type =~ /application\/x-www-form-urlencoded/
        is_head = request.methods.to_s.upcase == 'HEAD'
        is_get = request.methods.to_s.upcase == 'GET'

        # Spec says body_hash should not be sent if req is formencoded
        # or if req is HEAD or GET
        !(is_form_urlencoded || is_head || is_get)
      end

      def oauth_parameters(request)
        auth_headers = { 'oauth_consumer_key'     => CGI::escape(self.consumer_key),
          'oauth_token'            => CGI::escape(self.oauth_token),
          'oauth_signature_method' => "HMAC-SHA1",
          'oauth_timestamp'        => Time.now.to_i,
          'oauth_nonce'            => generate_nonce,
          'oauth_version'          => "1.0"
        }

        if need_body_hash?(request)
          auth_headers['oauth_body_hash'] = CGI::escape(calculate_body_hash(request))
        end

        auth_headers
      end

      # 2 ** 64, the largest 64 bit unsigned integer
      BIG_INT_MAX = 18446744073709551616
      def generate_nonce
        Digest::SHA1.hexdigest(OpenSSL::BN.rand_range(BIG_INT_MAX).to_s)
      end

      def calculate_body_hash(request)
        case request.body
        when String
          body = request.body
        when GData::HTTP::MimeBody
          body = ''
          while (chunk = request.body.read(1024))
            body << chunk
          end
          request.body.rewind
        when nil
          body = ''
        else
          body = request.body.to_s
        end

        body_hash = Digest::SHA1.digest(body)
        body_hash = [body_hash].pack("m").chomp # base64 encode
        body_hash
      end

      # NOTE: this will fail on formencoded bodies.
      def normalize_parameters(request, oauth_params)
        query_string = URI::parse(request.url).query
        params = {}
        if query_string
          q_params = query_string.split('&')
          q_params.each { |p| (k,v) = p.split('='); params[k] = v }
        end
        params.merge!(oauth_params)
        params.sort_by { |k,v| k }.map { |p| p.join('=') }.join('&')
      end

    end
  end
end
