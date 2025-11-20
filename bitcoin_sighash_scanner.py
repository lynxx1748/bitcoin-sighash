#!/usr/bin/env python3
"""
Bitcoin SIGHASH_SINGLE Bug Scanner

This educational tool scans the Bitcoin blockchain for addresses vulnerable 
to the SIGHASH_SINGLE bug. 

The bug: When using SIGHASH_SINGLE on an input where the input index is 
greater than or equal to the number of outputs, the signature hash becomes 
a constant value (0x01), making funds potentially vulnerable.
"""

import argparse
import logging
import sys
from decimal import Decimal, getcontext
from pathlib import Path
from typing import Dict, Tuple, Optional
from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException

# Configure decimal context to handle Bitcoin's precision
# Set high precision to avoid InvalidOperation errors
getcontext().prec = 28


# SIGHASH types
SIGHASH_ALL = 0x01
SIGHASH_NONE = 0x02
SIGHASH_SINGLE = 0x03
SIGHASH_ANYONECANPAY = 0x80


class BitcoinSigHashScanner:
    """Scanner for SIGHASH_SINGLE vulnerability in Bitcoin blockchain."""
    
    def __init__(self, rpc_url: str, rpc_user: str = None, rpc_password: str = None):
        """
        Initialize the scanner with RPC connection details.
        
        Args:
            rpc_url: URL of Bitcoin RPC server (e.g., http://127.0.0.1:8332)
            rpc_user: RPC username (if not using cookie auth)
            rpc_password: RPC password (if not using cookie auth)
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
            
        self.utxos: Dict[Tuple[str, int], dict] = {}
        
    def get_block_height(self) -> int:
        """Get the current blockchain height."""
        try:
            mining_info = self.rpc.getmininginfo()
            return mining_info['blocks']
        except JSONRPCException as e:
            logging.error(f"Failed to fetch blockchain height: {e}")
            raise
    
    def scan_blockchain(self, start_height: int = 0, end_height: Optional[int] = None):
        """
        Scan the blockchain for SIGHASH_SINGLE vulnerabilities.
        
        Args:
            start_height: Block height to start scanning from
            end_height: Block height to end scanning at (None = current height)
        """
        if end_height is None:
            end_height = self.get_block_height()
        
        logging.info(f"Starting scan from block {start_height} to {end_height}")
        logging.info(f"Total blocks to scan: {end_height - start_height + 1}")
        
        for height in range(start_height, end_height + 1):
            if height % 500 == 0:
                logging.info(f"Progress: Scanning block {height} / {end_height}")
            
            try:
                self._scan_block(height)
            except JSONRPCException as e:
                logging.error(f"Error scanning block {height}: {e}")
                logging.error("Is the Bitcoin daemon running?")
                raise
    
    def _scan_block(self, height: int):
        """Scan a single block for SIGHASH_SINGLE usage."""
        try:
            block_hash = self.rpc.getblockhash(height)
            block = self.rpc.getblock(block_hash, 2)  # Verbosity 2 = include transactions
        except JSONRPCException as e:
            logging.error(f"Failed to get block at height {height}: {e}")
            raise
        
        # Process all transactions in the block
        for tx in block['tx']:
            # Add outputs to UTXO set
            txid = tx['txid']
            for vout_idx, vout in enumerate(tx['vout']):
                self.utxos[(txid, vout_idx)] = vout
            
        # Skip coinbase transaction (first transaction)
        for tx in block['tx'][1:]:
            self._check_transaction(tx)
    
    def _check_transaction(self, tx: dict):
        """
        Check a transaction for SIGHASH_SINGLE vulnerability.
        
        The vulnerability occurs when:
        1. Input uses SIGHASH_SINGLE or SIGHASH_SINGLE|ANYONECANPAY
        2. Input index >= number of outputs in the transaction
        """
        output_count = len(tx['vout'])
        
        for input_idx, tx_input in enumerate(tx['vin']):
            # Skip coinbase inputs
            if 'coinbase' in tx_input:
                continue
            
            # Get the previous output (UTXO) being spent
            prev_txid = tx_input['txid']
            prev_vout = tx_input['vout']
            
            prev_output = self.utxos.pop((prev_txid, prev_vout), None)
            if prev_output is None:
                # UTXO not found (might have been spent in earlier block)
                continue
            
            # Only check if this input could trigger the bug
            # (input index >= output count)
            if input_idx < output_count:
                continue
            
            # Check if this is P2PKH or P2PK
            script_pub_key = prev_output.get('scriptPubKey', {})
            script_type = script_pub_key.get('type', '')
            
            if script_type not in ('pubkeyhash', 'pubkey'):
                continue
            
            # Extract sighash byte from signature
            sighash_byte = self._extract_sighash_from_input(tx_input)
            if sighash_byte is None:
                continue
            
            # Check if it's SIGHASH_SINGLE or SIGHASH_SINGLE|ANYONECANPAY
            sighash_type = sighash_byte & 0x1f  # Mask out ANYONECANPAY flag
            
            if sighash_type == SIGHASH_SINGLE:
                anyonecanpay = " | ANYONECANPAY" if (sighash_byte & SIGHASH_ANYONECANPAY) else ""
                logging.info(f"🔍 FOUND SIGHASH_SINGLE{anyonecanpay} vulnerability!")
                logging.info(f"   Transaction: {tx['txid']}, Input: {input_idx}")
                self._print_blockstream_links(tx['txid'], input_idx, script_pub_key)
    
    def _extract_sighash_from_input(self, tx_input: dict) -> Optional[int]:
        """
        Extract the sighash byte from a transaction input's signature.
        
        Returns:
            The sighash byte as an integer, or None if not found
        """
        script_sig_hex = tx_input.get('scriptSig', {}).get('hex', '')
        if not script_sig_hex:
            return None
        
        try:
            # Parse the scriptSig to extract the signature
            script_bytes = bytes.fromhex(script_sig_hex)
            
            if len(script_bytes) < 2:
                return None
            
            # First byte should be the push length
            sig_length = script_bytes[0]
            
            if len(script_bytes) < sig_length + 1:
                return None
            
            # Last byte of the signature is the sighash type
            sighash_byte = script_bytes[sig_length]
            
            return sighash_byte
            
        except (ValueError, IndexError):
            return None
    
    def _print_blockstream_links(self, txid: str, input_idx: int, script_pub_key: dict):
        """Print helpful Blockstream.info links for investigation."""
        logging.info(f"   🔗 Transaction: https://blockstream.info/tx/{txid}?input:{input_idx}&expand")
        
        # Extract address if available
        addresses = script_pub_key.get('addresses', [])
        if addresses:
            for addr in addresses:
                logging.info(f"   🔗 Address: https://blockstream.info/address/{addr}")
        elif 'address' in script_pub_key:
            logging.info(f"   🔗 Address: https://blockstream.info/address/{script_pub_key['address']}")


def find_bitcoin_cookie(bitcoin_dir: Optional[Path] = None) -> Path:
    """
    Find the Bitcoin cookie file for authentication.
    
    Args:
        bitcoin_dir: Custom Bitcoin directory, or None for default
        
    Returns:
        Path to the .cookie file
    """
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
    """
    Parse Bitcoin cookie file to get RPC credentials.
    
    Returns:
        Tuple of (username, password)
    """
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
        description='Bitcoin SIGHASH_SINGLE Bug Scanner - Educational Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example usage:
  %(prog)s --address 127.0.0.1:8332
  %(prog)s --address 127.0.0.1:8332 --bitcoin-dir ~/.bitcoin
  %(prog)s --address 127.0.0.1:8332 --log-file scan_results.log

This tool scans the Bitcoin blockchain for the SIGHASH_SINGLE bug.
Read more: https://github.com/MatanHamilis/sighash_post
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
        scanner = BitcoinSigHashScanner(rpc_url, rpc_user, rpc_password)
        scanner.scan_blockchain(args.start_height, args.end_height)
        logging.info("✅ Scan completed successfully!")
    except Exception as e:
        logging.error(f"Scanner error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()

