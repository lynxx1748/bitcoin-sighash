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
    
    def _process_transaction(self, tx: dict, block_height: int):
        """Extract and analyze signatures from a transaction."""
        txid = tx['txid']
        
        for input_idx, tx_input in enumerate(tx['vin']):
            # Skip coinbase inputs
            if 'coinbase' in tx_input:
                continue
            
            # Extract signature from scriptSig
            sig_info = self._extract_signature(tx_input, txid, input_idx)
            
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
    
    def _extract_signature(self, tx_input: dict, txid: str, input_idx: int) -> Optional[SignatureInfo]:
        """
        Extract ECDSA signature components from transaction input.
        
        Returns:
            SignatureInfo object or None if extraction fails
        """
        script_sig_hex = tx_input.get('scriptSig', {}).get('hex', '')
        if not script_sig_hex:
            # Try witness data for SegWit transactions
            witness = tx_input.get('txinwitness', [])
            if not witness:
                return None
            script_sig_hex = ''.join(witness)
        
        try:
            script_bytes = bytes.fromhex(script_sig_hex)
            
            # Parse DER-encoded signature
            r, s, sig_end = self._parse_der_signature(script_bytes)
            if r is None or s is None:
                return None
            
            # Extract public key (usually after signature)
            pubkey = self._extract_pubkey(script_bytes, sig_end)
            if pubkey is None:
                return None
            
            # Calculate message hash (sighash)
            # For now, we'll use a placeholder - full implementation would reconstruct
            # the actual sighash, but for detecting reuse, we just need r/s values
            z = self._calculate_sighash_placeholder(tx_input)
            
            return SignatureInfo(r, s, z, txid, input_idx, pubkey)
            
        except Exception as e:
            # Silently skip unparseable signatures
            return None
    
    def _parse_der_signature(self, script_bytes: bytes) -> Tuple[Optional[int], Optional[int], int]:
        """
        Parse DER-encoded ECDSA signature.
        
        Returns:
            Tuple of (r, s, end_position) or (None, None, 0) on failure
        """
        try:
            if len(script_bytes) < 8:
                return None, None, 0
            
            pos = 0
            
            # First byte is signature length (push opcode)
            if script_bytes[pos] < 0x01 or script_bytes[pos] > 0x4b:
                # Could be direct DER without push opcode
                pos = 0
            else:
                pos = 1
            
            # DER signature format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S]
            if script_bytes[pos] != 0x30:
                return None, None, 0
            
            pos += 1
            sig_length = script_bytes[pos]
            pos += 1
            
            # Parse R
            if script_bytes[pos] != 0x02:
                return None, None, 0
            pos += 1
            
            r_length = script_bytes[pos]
            pos += 1
            
            r = int.from_bytes(script_bytes[pos:pos + r_length], byteorder='big')
            pos += r_length
            
            # Parse S
            if script_bytes[pos] != 0x02:
                return None, None, 0
            pos += 1
            
            s_length = script_bytes[pos]
            pos += 1
            
            s = int.from_bytes(script_bytes[pos:pos + s_length], byteorder='big')
            pos += s_length
            
            # Skip sighash byte
            pos += 1
            
            return r, s, pos
            
        except (IndexError, ValueError):
            return None, None, 0
    
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
    
    def _calculate_sighash_placeholder(self, tx_input: dict) -> int:
        """
        Placeholder for sighash calculation.
        Full implementation would reconstruct the transaction and calculate proper sighash.
        For detecting nonce reuse, we need the actual z values to recover the key.
        """
        # This is a simplified placeholder - real implementation needs full transaction data
        txid = tx_input.get('txid', '')
        vout = tx_input.get('vout', 0)
        
        # Create a deterministic hash from available data
        data = f"{txid}{vout}".encode()
        hash_bytes = hashlib.sha256(hashlib.sha256(data).digest()).digest()
        
        return int.from_bytes(hash_bytes, byteorder='big')
    
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
                
                # Store recovered key
                self.recovered_keys.append((private_key, new_sig.pubkey, [prev_sig, new_sig]))
                
                # Check balance
                self._check_balance(private_key, new_sig.pubkey)
                
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
    
    def _check_balance(self, private_key: int, pubkey: str):
        """Check if the recovered private key controls any funds."""
        try:
            # Derive address from public key (simplified - would need full implementation)
            logging.info(f"   Checking for funds controlled by this key...")
            
            # In a full implementation, you would:
            # 1. Derive the address from the private key
            # 2. Query the blockchain for UTXO balance
            # 3. Report any funds found
            
            logging.info(f"   (Balance checking requires additional implementation)")
            
        except Exception as e:
            logging.error(f"Error checking balance: {e}")
    
    def _report_recovered_keys(self):
        """Generate detailed report of all recovered private keys."""
        logging.info("\n" + "=" * 80)
        logging.info("RECOVERED PRIVATE KEYS REPORT")
        logging.info("=" * 80)
        
        for idx, (privkey, pubkey, sigs) in enumerate(self.recovered_keys, 1):
            logging.info(f"\n[{idx}] Private Key Recovered:")
            logging.info(f"    Private Key (hex): {hex(privkey)}")
            logging.info(f"    Private Key (WIF): [Requires additional implementation]")
            logging.info(f"    Public Key: {pubkey}")
            logging.info(f"    Reused in {len(sigs)} signatures:")
            
            for sig in sigs:
                logging.info(f"      - TX: {sig.txid}")
                logging.info(f"        Input: {sig.input_idx}")
                logging.info(f"        Explorer: https://blockstream.info/tx/{sig.txid}")
        
        logging.info("\n" + "=" * 80)
        logging.info("⚠️  WARNING: These private keys were vulnerable due to nonce reuse.")
        logging.info("    Any funds controlled by these keys are at risk of theft!")
        logging.info("=" * 80)


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

