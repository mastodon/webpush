# frozen_string_literal: true

module Webpush
  # Class for abstracting the generation and encoding of elliptic curve public and private keys for use with the VAPID protocol
  #
  # @attr_reader [OpenSSL::PKey::EC] :curve the OpenSSL elliptic curve instance
  class VapidKey
    class << self
      # Create a VapidKey instance from encoded elliptic curve public and private keys
      #
      # @return [Webpush::VapidKey] a VapidKey instance for the given public and private keys
      def from_keys(public_key, private_key)
        if public_key.nil? && private_key.nil?
          new
        else
          # method is called `from_pem` and we are passing in a DER encoded string
          # but OpenSSL::PKey.read, called internally by `from_pem`, accepts both.
          self.from_pem(keys_to_der(public_key, private_key))
        end
      end

      # Create a VapidKey instance from pem encoded elliptic curve public and private keys
      #
      # @return [Webpush::VapidKey] a VapidKey instance for the given public and private keys
      def from_pem(pem)
        new(OpenSSL::PKey.read pem)
      end

      private

      # Encode the VAPID serialized base64 keys in DER form
      # This method uses either the public or private key. If both
      # are specified the public key is ignored.
      def keys_to_der(public_key, private_key)
        asn = if private_key.nil?
          public_key = OpenSSL::PKey::EC::Point.new(EC_GROUP, to_big_num(public_key))

          OpenSSL::ASN1::Sequence([
            OpenSSL::ASN1::Sequence([
              OpenSSL::ASN1::ObjectId('id-ecPublicKey'),
              OpenSSL::ASN1::ObjectId(EC_GROUP.curve_name),
            ]),
            OpenSSL::ASN1::BitString(public_key.to_octet_string(:uncompressed)),
          ])
        else
          private_key = to_big_num(private_key)

          OpenSSL::ASN1::Sequence([
            OpenSSL::ASN1::Integer.new(1),
            OpenSSL::ASN1::OctetString(private_key.to_s(2)),
            OpenSSL::ASN1::ObjectId(EC_GROUP.curve_name, 0, :EXPLICIT),
          ])
        end

        asn.to_der
      end

      def to_big_num(key)
        OpenSSL::BN.new(Webpush.decode64(key), 2)
      end
    end

    EC_GROUP = OpenSSL::PKey::EC::Group.new('prime256v1')

    attr_reader :curve

    def initialize(pkey = nil)
      @curve = pkey
      @curve ||= OpenSSL::PKey::EC.generate(EC_GROUP.curve_name)
    end

    # Retrieve the encoded elliptic curve public key for VAPID protocol
    #
    # @return [String] encoded binary representation of 65-byte VAPID public key
    def public_key
      @public_key_encoded ||= Webpush.encode64(curve.public_key.to_bn.to_s(2))
    end

    # Retrieve the encoded elliptic curve public key suitable for the Web Push request
    #
    # @return [String] the encoded VAPID public key for us in 'Encryption' header
    def public_key_for_push_header
      public_key.delete('=')
    end

    # Retrive the encoded elliptic curve private key for VAPID protocol
    #
    # @return [String] base64 urlsafe-encoded binary representation of 32-byte VAPID private key
    def private_key
      @private_key_encoded ||= Webpush.encode64(curve.private_key.to_s(2)) if curve.private?
    end

    def curve_name
      group.curve_name
    end

    def group
      curve.group
    end

    def to_h
      { public_key: public_key, private_key: private_key }.compact
    end
    alias to_hash to_h

    def to_pem
      curve.to_pem + curve.public_to_pem
    end

    def inspect
      "#<#{self.class}:#{object_id.to_s(16)} #{to_h.map { |k, v| ":#{k}=#{v}" }.join(' ')}>"
    end
  end
end
