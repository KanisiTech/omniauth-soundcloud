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
        if options.authorization_code_from_signed_request_in_cookie
          ''
        else
          # Fixes regression in omniauth-oauth2 v1.4.0 by https://github.com/intridea/omniauth-oauth2/commit/85fdbe117c2a4400d001a6368cc359d88f40abc7
          options[:callback_url] || (full_host + script_name + callback_path)
        end
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
          %w[display scope].each { |v| params[v.to_sym] = request.params[v] if request.params[v] }

          params[:scope] ||= DEFAULT_SCOPE
        end
      end

      def callback_phase
        state = session["omniauth.state"]
        result = super
        session["omniauth.state"] = state
        result
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
