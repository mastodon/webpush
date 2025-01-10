require 'spec_helper'

describe Webpush::Legacy::Encryption do
  describe '#encrypt' do
    let(:curve) do
      group = 'prime256v1'
      OpenSSL::PKey::EC.generate(group)
    end

    let(:p256dh) do
      ecdh_key = curve.public_key.to_bn.to_s(2)
      Base64.urlsafe_encode64(ecdh_key)
    end

    let(:auth) { Base64.urlsafe_encode64(Random.new.bytes(16)) }

    it 'returns ECDH encrypted cipher text, salt, and server_public_key' do
      payload = Webpush::Legacy::Encryption.encrypt('Hello World', p256dh, auth)
      expect(decrypt(payload)).to eq('Hello World')
    end

    it 'returns error when message is blank' do
      expect { Webpush::Legacy::Encryption.encrypt(nil, p256dh, auth) }.to raise_error(ArgumentError)
      expect { Webpush::Legacy::Encryption.encrypt('', p256dh, auth) }.to raise_error(ArgumentError)
    end

    it 'returns error when p256dh is blank' do
      expect { Webpush::Legacy::Encryption.encrypt('Hello world', nil, auth) }.to raise_error(ArgumentError)
      expect { Webpush::Legacy::Encryption.encrypt('Hello world', '', auth) }.to raise_error(ArgumentError)
    end

    it 'returns error when auth is blank' do
      expect { Webpush::Legacy::Encryption.encrypt('Hello world', p256dh, '') }.to raise_error(ArgumentError)
      expect { Webpush::Legacy::Encryption.encrypt('Hello world', p256dh, nil) }.to raise_error(ArgumentError)
    end

    # Bug fix for https://github.com/zaru/webpush/issues/22
    it 'handles unpadded base64 encoded subscription keys' do
      unpadded_p256dh = p256dh.gsub(/=*\Z/, '')
      unpadded_auth = auth.gsub(/=*\Z/, '')

      payload = Webpush::Legacy::Encryption.encrypt('Hello World', unpadded_p256dh, unpadded_auth)
      expect(decrypt(payload)).to eq('Hello World')
    end

    def decrypt(payload)
      salt = payload.fetch(:salt)
      serverkey16bn = payload.fetch(:server_public_key_bn)
      ciphertext = payload.fetch(:ciphertext)

      group_name = 'prime256v1'
      group = OpenSSL::PKey::EC::Group.new(group_name)
      server_public_key_bn = OpenSSL::BN.new(serverkey16bn.unpack('H*').first, 16)
      server_public_key = OpenSSL::PKey::EC::Point.new(group, server_public_key_bn)
      shared_secret = curve.dh_compute_key(server_public_key)

      client_public_key_bn = curve.public_key.to_bn
      client_auth_token = Webpush.decode64(auth)

      info = "Content-Encoding: auth\0"
      context = create_context(curve.public_key, server_public_key)
      content_encryption_key_info = "Content-Encoding: aesgcm\0P-256#{context}"
      nonce_info = "Content-Encoding: nonce\0P-256#{context}"

      prk = HKDF.new(shared_secret, salt: client_auth_token, algorithm: 'SHA256', info: info).next_bytes(32)

      content_encryption_key = HKDF.new(prk, salt: salt, info: content_encryption_key_info).next_bytes(16)
      nonce = HKDF.new(prk, salt: salt, info: nonce_info).next_bytes(12)

      decrypt_ciphertext(ciphertext, content_encryption_key, nonce)
    end

    def create_context(client_public_key, server_public_key)
      c = client_public_key.to_bn.to_s(2)
      s = server_public_key.to_bn.to_s(2)
      context = "\0"
      context += [c.bytesize].pack("n*")
      context += c
      context += [s.bytesize].pack("n*")
      context += s
      context
    end

    def decrypt_ciphertext(ciphertext, content_encryption_key, nonce)
      secret_data = ciphertext.byteslice(0, ciphertext.bytesize-16)
      auth = ciphertext.byteslice(ciphertext.bytesize-16, ciphertext.bytesize)
      decipher = OpenSSL::Cipher.new('aes-128-gcm')
      decipher.decrypt
      decipher.key = content_encryption_key
      decipher.iv = nonce
      decipher.auth_tag = auth

      decrypted = decipher.update(secret_data) + decipher.final

      e = decrypted.byteslice(0, 2)
      expect(e).to eq("\0\0")

      decrypted.byteslice(2, decrypted.bytesize-2)
    end
  end
end
