require 'omniauth/strategies/oauth2'

module OmniAuth
  module Strategies
    class SoundCloud < OmniAuth::Strategies::OAuth2
      DEFAULT_SCOPE = ''

      option :name, "soundcloud"

      option :client_options, {
        :site => 'https://api.soundcloud.com',
        :authorize_url => '/connect',
        :token_url => '/oauth2/token'
      }

      option :access_token_options, {
        :header_format => 'OAuth %s',
        :param_name => 'access_token'
      }

      uid { raw_info['id'] }

      info do
        prune!({
          'nickname' => raw_info['username'],
          'name' => raw_info['full_name'],
          'image' => raw_info['avatar_url'],
          'description' => raw_info['description'],
          'urls' => {
            'Website' => raw_info['website']
          },
          'location' => raw_info['city']
        })
      end

      credentials do
        prune!({
          'expires' => access_token.expires?,
          'expires_at' => access_token.expires_at
        })
      end

      extra do
        prune!({
          'raw_info' => raw_info
        })
      end

      def callback_url
        full_host + script_name + callback_path
      end

      def raw_info
        @raw_info ||= access_token.get('/me.json').parsed
      end

      def build_access_token
        super.tap do |token|
          token.options.merge!(access_token_options)
        end
      end

      def access_token_options
        options.access_token_options.inject({}) { |h,(k,v)| h[k.to_sym] = v; h }
      end

      def authorize_params
        super.tap do |params|
          %w[display state scope].each { |v| params[v.to_sym] = request.params[v] if request.params[v] }
          session['omniauth.state'] = params[:state] if params['state']

          params[:scope] ||= DEFAULT_SCOPE
        end
      end

      def callback_phase
        error = request.params["error_reason"] || request.params["error"]
        if error
          fail!(error, CallbackError.new(request.params["error"], request.params["error_description"] || request.params["error_reason"], request.params["error_uri"]))
        elsif !options.provider_ignores_state && (request.params["state"].to_s.empty? || request.params["state"] != session["omniauth.state"])
          fail!(:csrf_detected, CallbackError.new(:csrf_detected, "CSRF detected"))
        else
          self.access_token = build_access_token
          self.access_token = access_token.refresh! if access_token.expired?
          super
        end
      rescue ::OAuth2::Error, CallbackError => e
        fail!(:invalid_credentials, e)
      rescue ::Timeout::Error, ::Errno::ETIMEDOUT => e
        fail!(:timeout, e)
      rescue ::SocketError => e
        fail!(:failed_to_connect, e)
      end

      private

      def prune!(hash)
        hash.delete_if do |_, value|
          prune!(value) if value.is_a?(Hash)
          value.nil? || (value.respond_to?(:empty?) && value.empty?)
        end
      end
    end
  end
end

OmniAuth.config.add_camelization 'soundcloud', 'SoundCloud'
