# frozen_string_literal: true

module Webpush
  module Legacy
    module Encryption
      # This implements RFC8291 draft 4:
      # https://datatracker.ietf.org/doc/html/draft-ietf-webpush-encryption-04

      extend self

      def encrypt(message, p256dh, auth)
        assert_arguments(message, p256dh, auth)
  
        group_name = 'prime256v1'
        salt = Random.new.bytes(16)
  
        server = OpenSSL::PKey::EC.generate(group_name)
        server_public_key_bn = server.public_key.to_bn
  
        group = OpenSSL::PKey::EC::Group.new(group_name)
        client_public_key_bn = OpenSSL::BN.new(Webpush.decode64(p256dh), 2)
        client_public_key = OpenSSL::PKey::EC::Point.new(group, client_public_key_bn)
  
        shared_secret = server.dh_compute_key(client_public_key)
  
        client_auth_token = Webpush.decode64(auth)
  
        prk = HKDF.new(shared_secret, salt: client_auth_token, algorithm: 'SHA256', info: "Content-Encoding: auth\0").next_bytes(32)
  
        context = create_context(client_public_key_bn, server_public_key_bn)
  
        content_encryption_key_info = create_info('aesgcm', context)
        content_encryption_key = HKDF.new(prk, salt: salt, info: content_encryption_key_info).next_bytes(16)
  
        nonce_info = create_info('nonce', context)
        nonce = HKDF.new(prk, salt: salt, info: nonce_info).next_bytes(12)
  
        ciphertext = encrypt_payload(message, content_encryption_key, nonce)
  
        {
          ciphertext: ciphertext,
          salt: salt,
          server_public_key_bn: server_public_key_bn.to_s(2),
          server_public_key: server_public_key_bn.to_s(2),
          shared_secret: shared_secret
        }
      end

      private
  
      def assert_arguments(message, p256dh, auth)
        raise ArgumentError, 'message cannot be blank' if blank?(message)
        raise ArgumentError, 'p256dh cannot be blank' if blank?(p256dh)
        raise ArgumentError, 'auth cannot be blank' if blank?(auth)
      end
  
      def blank?(value)
        value.nil? || value.empty?
      end

      def create_context(client_public_key, server_public_key)
        c = client_public_key.to_s(2)
        s = server_public_key.to_s(2)
        "\0#{[c.bytesize].pack('n*')}#{c}#{[s.bytesize].pack('n*')}#{s}"
      end

      def encrypt_payload(plaintext, content_encryption_key, nonce)
        cipher = OpenSSL::Cipher.new('aes-128-gcm')
        cipher.encrypt
        cipher.key = content_encryption_key
        cipher.iv = nonce
        padding = cipher.update("\0\0")
        text = cipher.update(plaintext)

        e_text = padding + text + cipher.final
        e_tag = cipher.auth_tag
  
        e_text + e_tag
      end

      def create_info(type, context)
        "Content-Encoding: #{type}\0P-256#{context}"
      end
    end
  end
end