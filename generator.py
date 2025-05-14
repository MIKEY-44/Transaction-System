from eth_account import Account
import secrets

# Generate random private key
private_key = "0x" + secrets.token_hex(32)
print("Private Key:", private_key)

# Get public key (address)
acct = Account.from_key(private_key)
print("Address:", acct.address)
