#!/usr/bin/env python3
"""
Debug script to check signature extraction.
Tests if we can extract signatures from real blockchain transactions.
"""

import sys
from pathlib import Path
from bitcoinrpc.authproxy import AuthServiceProxy

def find_bitcoin_cookie():
    """Find Bitcoin cookie file."""
    home = Path.home()
    if sys.platform == 'win32':
        bitcoin_dir = home / 'AppData' / 'Roaming' / 'Bitcoin'
    else:
        bitcoin_dir = home / '.bitcoin'
    
    cookie_path = bitcoin_dir / '.cookie'
    return cookie_path

def parse_cookie_file(cookie_path):
    """Parse cookie file."""
    cookie_content = cookie_path.read_text().strip()
    username, password = cookie_content.split(':', 1)
    return username, password

def test_signature_extraction():
    """Test signature extraction on real blocks."""
    
    # Connect to Bitcoin RPC
    cookie_path = find_bitcoin_cookie()
    username, password = parse_cookie_file(cookie_path)
    
    rpc = AuthServiceProxy(f"http://{username}:{password}@127.0.0.1:8332", timeout=120)
    
    print("=" * 80)
    print("SIGNATURE EXTRACTION DEBUG TEST")
    print("=" * 80)
    
    # Test on a few early blocks with known transactions
    test_blocks = [170, 500, 1000, 10000]
    
    for height in test_blocks:
        print(f"\n[Block {height}]")
        
        try:
            block_hash = rpc.getblockhash(height)
            block = rpc.getblock(block_hash, 2)
            
            tx_count = len(block['tx'])
            print(f"  Transactions in block: {tx_count}")
            
            # Check non-coinbase transactions
            sig_count = 0
            for tx in block['tx'][1:]:  # Skip coinbase
                txid = tx['txid']
                
                for input_idx, tx_input in enumerate(tx['vin']):
                    if 'coinbase' in tx_input:
                        continue
                    
                    # Check scriptSig
                    script_sig_hex = tx_input.get('scriptSig', {}).get('hex', '')
                    witness = tx_input.get('txinwitness', [])
                    
                    if script_sig_hex:
                        sig_count += 1
                        print(f"  TX {txid[:16]}... Input {input_idx}: scriptSig found ({len(script_sig_hex)} chars)")
                        print(f"    First 100 chars: {script_sig_hex[:100]}")
                        
                        # Try to parse DER signature
                        try:
                            script_bytes = bytes.fromhex(script_sig_hex)
                            print(f"    Hex decoded: {len(script_bytes)} bytes")
                            print(f"    First 20 bytes: {script_bytes[:20].hex()}")
                            
                            # Check for DER signature marker (0x30)
                            if len(script_bytes) > 2:
                                if script_bytes[0] >= 0x01 and script_bytes[0] <= 0x4b:
                                    print(f"    Push opcode: {script_bytes[0]}")
                                    if script_bytes[1] == 0x30:
                                        print(f"    ✅ DER signature detected!")
                                elif script_bytes[0] == 0x30:
                                    print(f"    ✅ DER signature detected (no push)!")
                        except Exception as e:
                            print(f"    ❌ Error parsing: {e}")
                    
                    elif witness:
                        sig_count += 1
                        print(f"  TX {txid[:16]}... Input {input_idx}: witness found ({len(witness)} items)")
                        print(f"    Witness[0] (sig): {witness[0][:100]}")
            
            print(f"  Total signatures found: {sig_count}")
            
            if sig_count == 0:
                print(f"  ⚠️  WARNING: No signatures found in block!")
        
        except Exception as e:
            print(f"  ❌ Error: {e}")
            import traceback
            traceback.print_exc()
    
    print("\n" + "=" * 80)
    print("DEBUG TEST COMPLETE")
    print("=" * 80)

if __name__ == '__main__':
    test_signature_extraction()

================================================================================
SIGNATURE EXTRACTION DEBUG TEST
================================================================================

[Block 170]
  Transactions in block: 2
  TX f4184fc596403b9d... Input 0: scriptSig found (144 chars)
    First 100 chars: 47304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4
    Hex decoded: 72 bytes
    First 20 bytes: 47304402204e45e16932b8af514961a1d3a1a25f
    Push opcode: 71
    ✅ DER signature detected!
  Total signatures found: 1

[Block 500]
  Transactions in block: 1
  Total signatures found: 0
  ⚠️  WARNING: No signatures found in block!

[Block 1000]
  Transactions in block: 1
  Total signatures found: 0
  ⚠️  WARNING: No signatures found in block!

[Block 10000]
  Transactions in block: 1
  Total signatures found: 0
  ⚠️  WARNING: No signatures found in block!

================================================================================
DEBUG TEST COMPLETE
================================================================================
