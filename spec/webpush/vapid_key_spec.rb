require 'spec_helper'

describe Webpush::VapidKey do
  it 'generates an elliptic curve' do
    key = Webpush::VapidKey.new
    expect(key.curve).to be_a(OpenSSL::PKey::EC)
    expect(key.curve_name).to eq('prime256v1')
  end

  it 'returns an encoded public key' do
    key = Webpush::VapidKey.new

    expect(Base64.urlsafe_decode64(key.public_key).bytesize).to eq(65)
  end

  it 'returns an encoded private key' do
    key = Webpush::VapidKey.new

    expect(Base64.urlsafe_decode64(key.private_key).bytesize).to eq(32)
  end

  it 'pretty prints encoded keys' do
    key = Webpush::VapidKey.new
    printed = key.inspect

    expect(printed).to match(/public_key=#{key.public_key}/)
    expect(printed).to match(/private_key=#{key.private_key}/)
  end

  it 'returns hash of public and private keys' do
    key = Webpush::VapidKey.new
    hash = key.to_h

    expect(hash[:public_key]).to eq(key.public_key)
    expect(hash[:private_key]).to eq(key.private_key)
  end

  it 'returns pem of public and private keys' do
    key = Webpush::VapidKey.new
    pem = key.to_pem

    expect(pem).to include('-----BEGIN EC PRIVATE KEY-----')
    expect(pem).to include('-----BEGIN PUBLIC KEY-----')
  end

  it 'imports pem of public and private keys' do
    pem = Webpush::VapidKey.new.to_pem
    key = Webpush::VapidKey.from_pem pem

    expect(key.to_pem).to eq(pem)
  end

  describe 'self.from_keys' do
    it 'returns an encoded public key' do
      key = Webpush::VapidKey.from_keys(nil, vapid_private_key)

      expect(key.public_key).to eq(vapid_public_key)
    end

    it 'returns an encoded private key' do
      key = Webpush::VapidKey.from_keys(nil, vapid_private_key)

      expect(key.private_key).to eq(vapid_private_key)
    end

    it 'initializes properly with a public key only' do
      key = Webpush::VapidKey.from_keys(vapid_public_key, nil)

      expect(key.public_key).to eq(vapid_public_key)
      expect(key.private_key).to be_nil
    end

    it 'ignores the public key when the private key is provided' do
      key = Webpush::VapidKey.from_keys('notavalidpublickey', vapid_private_key)

      expect(key.public_key).to eq(vapid_public_key)
    end
  end
end
