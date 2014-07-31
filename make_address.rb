#!/usr/bin/env ruby

require 'openssl'
require 'base58'
require 'digest'
include OpenSSL

#Step by Step Bitcion WIF and Public Address generator
#Generates a usable bitcoin WIF and Public Address, showing anatomy of the spec.
#Probably insecure, don't use these in a wallet or to store funds.
#All hashing is done on binary data, though we bounce in between hex/binary to send to STD out


#These were made along these guides:
#https://en.bitcoin.it/wiki/Protocol_specification#Addresses
#https://en.bitcoin.it/wiki/Wallet_import_format
#http://gobittest.appspot.com/PrivateKey
#http://gobittest.appspot.com/Address


#Bitcoin defines a custom base58 implementation, which we implement here.
#These are ripped from bitcoin-ruby and lianj!
#https://github.com/lian/bitcoin-ruby
def encode_base58(hex)
 leading_zero_bytes  = (hex.match(/^([0]+)/) ? $1 : '').size / 2
 ("1"*leading_zero_bytes) + int_to_base58( hex.to_i(16) )
end

def int_to_base58(int_val, leading_zero_bytes=0)
#This string is the real magic making bitcoin's base58 implementation different.
  alpha = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
  base58_val, base = '', alpha.size
  while int_val > 0
    int_val, remainder = int_val.divmod(base)
    base58_val = alpha[remainder] + base58_val
  end
  base58_val
end

#Generate the underlying keypair with OpenSSL. We need to use EC crypto and secp256k1 parameters
key=PKey::EC.new('secp256k1')
key=key.generate_key

puts "#Creating Private Key into Wallet Interchangeable Format (WIF)"
puts "1. Private Key (No Hex): #{key.private_key}"
puts "2. Private Key (Hex): #{key.private_key.to_s(16)}"

#Throwing a byte in front that indicates we're using 'mainnet', which is the actual BTC network. There's a testnet as well.
pre_sha = "80#{key.private_key.to_s(16)}"
puts '3. Add leading 0x80 Byte: ' + pre_sha

#We convert to binary before hashing. This is a big 'gotcha'
bin_pre_sha = [pre_sha].pack('H*')

#First round of SHA256
round_one = Digest::SHA256.hexdigest bin_pre_sha
puts "4. SHA256 Round 1: #{round_one}"

#Second round of SHA256. Oddly, we have to convert the first round 
#SHA256 hash into Binary too.
round_two = Digest::SHA256.hexdigest [round_one].pack('H*');
puts "5. SHA256 Round 2: #{round_two}"

#First four bytes of round_two is the checksum
checksum = round_two[0,8];
puts "6. Checksum: #{checksum}";

#Add the checksum at the end
pre_base58 = "#{pre_sha}#{checksum}"
puts "7. Pre-Base58: #{pre_base58}"

#Base58 it
base58_key = encode_base58(pre_base58)
puts "8. WIF: #{base58_key}"

puts ""
puts "#Deriving BTC Address from Public Key"

#Now we show the public key
ecdsa_pubkey = key.public_key.to_bn.to_s(16)
puts "1. Public ECDSA Key: #{ecdsa_pubkey}"

#PubKey with round one SHA256
ecdsa_pubkey_round_one = Digest::SHA256.hexdigest [ecdsa_pubkey].pack('H*')
puts "2. SHA256 Round 1: #{ecdsa_pubkey_round_one}" 

#PubKey with round two SHA256
ripemd_pubkey_round_one = Digest::RMD160.hexdigest [ecdsa_pubkey_round_one].pack('H*')
puts "3. RIPEMD Round 1: #{ripemd_pubkey_round_one}"

#Add Network Byes
network_pubkey = "00" + ripemd_pubkey_round_one
puts "4. Add Network Bytes: #{network_pubkey}"

#Round one SHA
network_pubkey_sha_one = Digest::SHA256.hexdigest [network_pubkey].pack('H*')
puts "5. Round One SHA #{network_pubkey_sha_one}"

#Round Two SHA
network_pubkey_sha_two = Digest::SHA256.hexdigest [network_pubkey_sha_one].pack('H*')
puts "6. Round Two SHA #{network_pubkey_sha_two}"

#First four Bytes
pub_checksum = network_pubkey_sha_two[0,8]
puts "7. Public Key Checksum: #{pub_checksum}"

#Combine Checksum
pre_base58_pub = "#{network_pubkey}#{pub_checksum}"
puts "8. Pre-Base58: #{pre_base58_pub}"

#Public Address
pub_address = encode_base58(pre_base58_pub)
puts "9. Public Address: #{pub_address}"
