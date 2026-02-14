"""
SIMON Lightweight Block Cipher - Differential Cryptanalysis Implementation
Project: Applied Cryptography - Differential Analysis of SIMON 128/128
Authors: Priyanshu Ranjan, Muhammed Ajlan, Manish Kumar, Sahil Verma
Faculty Advisor: Dr. Kakali Chatterjee
National Institute of Technology Patna

This module provides complete implementation of SIMON cipher and differential
cryptanalysis attacks for educational and research purposes.
"""

import numpy as np
from collections import defaultdict
from typing import Tuple, List, Dict, Set
import struct
import os
import json

# ============================================================================
# CORE SIMON CIPHER IMPLEMENTATION
# ============================================================================

class SIMON:
    """
    SIMON Lightweight Block Cipher
    Supports variants: SIMON 32/64, SIMON 48/72, SIMON 48/96, SIMON 64/96, 
                       SIMON 64/128, SIMON 96/92, SIMON 96/144, SIMON 128/128,
                       SIMON 128/192, SIMON 128/256
    """
    
    # Z sequence constants from NSA specification
    Z = [
        [1,1,1,1,1,0,0,0,1,0,0,1,0,1,0,1,1,0,0,0,0,1,1,1,0,0,1,1,0,1,1,1],
        [1,0,0,0,1,1,1,0,0,1,1,0,1,0,1,0,1,0,0,1,0,1,1,1,0,0,1,1,0,1,1,1],
        [1,0,1,0,1,1,1,1,0,1,1,1,0,0,1,0,1,0,1,1,0,0,0,1,0,1,0,0,0,0,1,1],
        [1,1,0,1,1,0,1,1,1,0,1,0,1,1,0,0,0,0,1,1,0,0,1,1,0,1,0,0,0,0,1,0],
        [1,1,0,1,0,0,1,1,0,1,0,1,1,1,1,0,0,1,1,0,0,1,0,1,0,0,0,1,0,0,1,0]
    ]
    
    PARAMS = {
        32: {'words': 4, 'rounds': 32, 'z_idx': 0},
        48: {'words': 3, 'rounds': 36, 'z_idx': 0},
        64: {'words': 3, 'rounds': 42, 'z_idx': 2},
        96: {'words': 2, 'rounds': 52, 'z_idx': 2},
        128: {'words': 2, 'rounds': 68, 'z_idx': 2}
    }
    
    def _init_(self, key: bytes, block_size: int = 128):
        """Initialize SIMON cipher with master key"""
        if block_size not in self.PARAMS:
            raise ValueError(f"Unsupported block size: {block_size}")
        
        self.block_size = block_size
        self.n = block_size // 2
        self.params = self.PARAMS[block_size]
        self.key = key
        self.round_keys = self._expand_key(key)
    
    @staticmethod
    def _rotl(x: int, n: int, bits: int) -> int:
        """Left rotate x by n positions within bits width"""
        mask = (1 << bits) - 1
        n = n % bits
        return ((x << n) | (x >> (bits - n))) & mask
    
    @staticmethod
    def _rotr(x: int, n: int, bits: int) -> int:
        """Right rotate x by n positions within bits width"""
        mask = (1 << bits) - 1
        n = n % bits
        return ((x >> n) | (x << (bits - n))) & mask
    
    def _f_function(self, x: int) -> int:
        """SIMON round function: F(x) = ((x <<<8) & (x <<<1)) ^ (x <<<2)"""
        x_max = (1 << self.n) - 1
        return ((self._rotl(x, 8, self.n) & self._rotl(x, 1, self.n)) ^ 
                self._rotl(x, 2, self.n)) & x_max
    
    def _expand_key(self, key: bytes) -> List[int]:
        """Key schedule for SIMON"""
        words = self.params['words']
        rounds = self.params['rounds']
        z_idx = self.params['z_idx']
        c_const = (1 << self.n) - 1 - 3
        
        # Parse master key into words
        key_words = []
        key_int = int.from_bytes(key, 'little')
        for i in range(words):
            word = (key_int >> (i * self.n)) & ((1 << self.n) - 1)
            key_words.append(word)
        
        # Expand to round keys
        round_keys = key_words[:]
        z_seq = self.Z[z_idx]
        
        for i in range(words, rounds):
            if words == 2:
                temp = round_keys[i - 1]
                temp = self._rotr(temp, 3, self.n) ^ round_keys[i - 2]
                temp = temp ^ self._rotr(temp, 1, self.n)
            elif words == 3:
                temp = round_keys[i - 1]
                temp = self._rotr(temp, 3, self.n) ^ round_keys[i - 3]
                temp = temp ^ self._rotr(temp, 1, self.n)
            elif words == 4:
                temp = round_keys[i - 1]
                temp = (self._rotr(temp, 3, self.n) ^ round_keys[i - 3] ^
                        self._rotr(round_keys[i - 3] ^ self._rotr(temp, 3, self.n), 1, self.n))
            else:
                raise ValueError("Invalid key words")
            
            z_bit = z_seq[(i - words) % len(z_seq)]
            temp ^= c_const ^ z_bit
            round_keys.append(temp)
        
        return round_keys
    
    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt plaintext"""
        if len(plaintext) != self.block_size // 8:
            raise ValueError(f"Invalid plaintext length")
        
        pt_int = int.from_bytes(plaintext, 'little')
        left = pt_int & ((1 << self.n) - 1)
        right = (pt_int >> self.n) & ((1 << self.n) - 1)
        
        for i in range(self.params['rounds']):
            temp = right
            right = (left ^ self._f_function(right) ^ 
                    self.round_keys[i]) & ((1 << self.n) - 1)
            left = temp
        
        ciphertext = (right << self.n) | left
        return ciphertext.to_bytes(self.block_size // 8, 'little')
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt ciphertext"""
        if len(ciphertext) != self.block_size // 8:
            raise ValueError("Invalid ciphertext length")
        
        ct_int = int.from_bytes(ciphertext, 'little')
        left = ct_int & ((1 << self.n) - 1)
        right = (ct_int >> self.n) & ((1 << self.n) - 1)
        
        for i in range(self.params['rounds'] - 1, -1, -1):
            temp = left
            left = (right ^ self._f_function(left) ^ 
                   self.round_keys[i]) & ((1 << self.n) - 1)
            right = temp
        
        plaintext = (left << self.n) | right
        return plaintext.to_bytes(self.block_size // 8, 'little')
    
    def encrypt_rounds(self, plaintext: bytes, num_rounds: int) -> bytes:
        """Encrypt plaintext for specified number of rounds"""
        if len(plaintext) != self.block_size // 8:
            raise ValueError("Invalid plaintext length")
        if num_rounds > self.params['rounds']:
            raise ValueError(f"Cannot exceed {self.params['rounds']} rounds")
        
        pt_int = int.from_bytes(plaintext, 'little')
        left = pt_int & ((1 << self.n) - 1)
        right = (pt_int >> self.n) & ((1 << self.n) - 1)
        
        for i in range(num_rounds):
            temp = right
            right = (left ^ self._f_function(right) ^ 
                    self.round_keys[i]) & ((1 << self.n) - 1)
            left = temp
        
        ciphertext = (right << self.n) | left
        return ciphertext.to_bytes(self.block_size // 8, 'little')


# ============================================================================
# DIFFERENTIAL ANALYSIS FRAMEWORK
# ============================================================================

class DifferentialAnalyzer:
    """Differential cryptanalysis tools for SIMON"""
    
    def _init_(self, block_size: int = 128):
        self.block_size = block_size
        self.n = block_size // 2
        self.cipher_ref = SIMON(b'\x00' * (block_size // 8), block_size)
    
    def compute_f_differential_probability(self, input_diff: int, 
                                          output_diff: int,
                                          samples: int = None) -> float:
        """
        Compute probability that F(x) ^ F(x ^ input_diff) = output_diff
        """
        if samples is None:
            samples = min(2 ** 16, 2 ** self.n)
        
        count = 0
        mask = (1 << self.n) - 1
        
        for x in range(samples):
            f_x = self.cipher_ref._f_function(x)
            f_x_diff = self.cipher_ref._f_function((x ^ input_diff) & mask)
            
            if (f_x ^ f_x_diff) == output_diff:
                count += 1
        
        return count / samples if samples > 0 else 0.0
    
    def find_best_differentials(self, max_input_diff: int = 1000) -> Dict[int, float]:
        """
        Find high-probability differentials
        Returns dict mapping (input_diff, output_diff) to probability
        """
        best_diffs = {}
        
        for input_diff in range(1, max_input_diff):
            # For efficiency, sample output differences
            for output_diff in range(max_input_diff):
                prob = self.compute_f_differential_probability(input_diff, output_diff)
                
                if prob > 0.01:  # Threshold
                    best_diffs[(input_diff, output_diff)] = prob
        
        # Sort by probability
        return dict(sorted(best_diffs.items(), 
                          key=lambda x: x[1], reverse=True)[:100])
    
    def trace_difference_propagation(self, initial_diff: int, 
                                    num_rounds: int) -> List[Dict]:
        """
        Trace difference propagation through SIMON rounds
        Returns list of (possible_diffs, probabilities) for each round
        """
        trace = []
        current_diffs = {initial_diff: 1.0}
        
        for round_num in range(num_rounds):
            next_diffs = defaultdict(float)
            
            # For Feistel: if R_i has difference, R_i+1 = L_i ^ F(R_i)
            # So output difference involves F's differential property
            
            for diff, prob in current_diffs.items():
                if bin(diff).count('1') <= 3:  # Limit Hamming weight for efficiency
                    # Sample output differences
                    for test_out in range(min(100, 1 << self.n)):
                        dp = self.compute_f_differential_probability(diff, test_out)
                        if dp > 0:
                            next_diffs[test_out] += prob * dp
            
            # Keep top 20 differences to avoid explosion
            top_diffs = dict(sorted(next_diffs.items(), 
                                   key=lambda x: x[1], reverse=True)[:20])
            
            trace.append({
                'round': round_num,
                'differences': top_diffs,
                'total_probability': sum(top_diffs.values())
            })
            
            current_diffs = top_diffs
        
        return trace


# ============================================================================
# ATTACK IMPLEMENTATIONS
# ============================================================================

class DifferentialKeyRecoveryAttack:
    """Differential key recovery attack on SIMON"""
    
    def _init_(self, block_size: int = 128):
        self.block_size = block_size
        self.n = block_size // 2
    
    def mount_reduced_attack(self, 
                            target_key: bytes,
                            input_diff: int,
                            attack_rounds: int,
                            num_pairs: int = 100) -> Dict:
        """
        Mount differential attack on reduced-round SIMON
        
        Args:
            target_key: Secret key to attack
            input_diff: Input difference pattern
            attack_rounds: Number of rounds to attack
            num_pairs: Number of plaintext pairs to use
        
        Returns:
            Attack results including ranked key candidates
        """
        
        cipher = SIMON(target_key, self.block_size)
        
        # Key recovery scoring
        key_scores = defaultdict(int)
        total_pairs_filtered = 0
        
        # Generate chosen plaintext pairs
        for pair_idx in range(num_pairs):
            # Create plaintext pair with controlled difference
            p1 = pair_idx.to_bytes(self.block_size // 8, 'little')
            
            # XOR to create pair with input_diff
            p1_int = int.from_bytes(p1, 'little')
            p2_int = p1_int ^ input_diff
            p2 = p2_int.to_bytes(self.block_size // 8, 'little')
            
            # Encrypt both plaintexts for full rounds
            c1 = cipher.encrypt(p1)
            c2 = cipher.encrypt(p2)
            
            # Parse ciphertexts
            c1_int = int.from_bytes(c1, 'little')
            c2_int = int.from_bytes(c2, 'little')
            
            c1_left = c1_int & ((1 << self.n) - 1)
            c1_right = (c1_int >> self.n) & ((1 << self.n) - 1)
            c2_left = c2_int & ((1 << self.n) - 1)
            c2_right = (c2_int >> self.n) & ((1 << self.n) - 1)
            
            # Key recovery: test all possible last round keys
            for key_guess in range(min(1 << 16, 1 << self.n)):  # Limit for efficiency
                # Partial decryption with guessed key
                f_c1r = cipher._f_function(c1_right)
                f_c2r = cipher._f_function(c2_right)
                
                u1_left = (c1_right ^ f_c1r ^ c1_left ^ key_guess) & ((1 << self.n) - 1)
                u2_left = (c2_right ^ f_c2r ^ c2_left ^ key_guess) & ((1 << self.n) - 1)
                
                # Verify one more round
                check_diff = (cipher._f_function(u1_left) ^ 
                            cipher._f_function(u2_left) ^
                            c1_right ^ c2_right)
                
                if check_diff == 0:
                    key_scores[key_guess] += 1
                    total_pairs_filtered += 1
        
        # Rank keys
        ranked_keys = sorted(key_scores.items(), 
                            key=lambda x: x[1], reverse=True)
        
        return {
            'total_pairs': num_pairs,
            'pairs_passed_filter': total_pairs_filtered,
            'ranked_keys': ranked_keys[:20],
            'top_key_candidate': ranked_keys[0][0] if ranked_keys else None,
            'filtering_rate': total_pairs_filtered / num_pairs if num_pairs > 0 else 0
        }


# ============================================================================
# TESTING AND DEMONSTRATION
# ============================================================================

def run_cipher_verification():
    """Verify SIMON cipher correctness"""
    print("\n" + "="*70)
    print("SIMON CIPHER VERIFICATION")
    print("="*70)
    
    test_vectors = [
        {
            'key': b'\x00' * 16,
            'plaintext': b'\x00' * 16,
            'block_size': 128,
            'rounds': 1
        },
        {
            'key': b'\xff' * 16,
            'plaintext': b'\x00' * 16,
            'block_size': 128,
            'rounds': 1
        }
    ]
    
    for i, test in enumerate(test_vectors, 1):
        cipher = SIMON(test['key'], test['block_size'])
        ciphertext = cipher.encrypt(test['plaintext'])
        decrypted = cipher.decrypt(ciphertext)
        
        status = "✓ PASS" if decrypted == test['plaintext'] else "✗ FAIL"
        print(f"Test {i}: {status}")
        print(f"  Key: {test['key'].hex()[:32]}...")
        print(f"  PT:  {test['plaintext'].hex()}")
        print(f"  CT:  {ciphertext.hex()}")
        print()


def run_differential_analysis():
    """Run differential analysis demonstration"""
    print("\n" + "="*70)
    print("DIFFERENTIAL ANALYSIS")
    print("="*70)
    
    analyzer = DifferentialAnalyzer(block_size=128)
    
    print("\nComputing F-function differentials...")
    
    # Test specific differentials
    test_diffs = [1, 2, 4, 8, 16, 32, 64, 128]
    
    for input_diff in test_diffs:
        prob = analyzer.compute_f_differential_probability(input_diff, input_diff)
        print(f"Pr(0x{input_diff:04x} → 0x{input_diff:04x}) = {prob:.6f}")


def run_key_recovery_demo():
    """Demonstrate key recovery attack"""
    print("\n" + "="*70)
    print("KEY RECOVERY ATTACK DEMONSTRATION")
    print("="*70)
    print("(Reduced parameters for demonstration)\n")
    
    target_key = b'\x12\x34\x56\x78' * 4
    
    attack = DifferentialKeyRecoveryAttack(block_size=128)
    
    results = attack.mount_reduced_attack(
        target_key=target_key,
        input_diff=0x0001,
        attack_rounds=10,
        num_pairs=50
    )
    
    print(f"Target Key: {target_key.hex()}")
    print(f"Input Difference: 0x0001")
    print(f"\nAttack Results:")
    print(f"  Pairs used: {results['total_pairs']}")
    print(f"  Pairs passed filter: {results['pairs_passed_filter']}")
    print(f"  Filtering rate: {results['filtering_rate']:.2%}")
    print(f"\nTop 5 Key Candidates:")
    for rank, (key_cand, score) in enumerate(results['ranked_keys'][:5], 1):
        print(f"  {rank}. Key=0x{key_cand:016x}, Score={score}")


if _name_ == "_main_":
    print("\n" + "#"*70)
    print("# SIMON CRYPTANALYSIS - IMPLEMENTATION DEMONSTRATION")
    print("# National Institute of Technology Patna")
    print("#"*70)
    
    run_cipher_verification()
    run_differential_analysis()
    run_key_recovery_demo()
    
    print("\n" + "#"*70)
    print("# Demonstration Complete")
    print("#"*70 + "\n")