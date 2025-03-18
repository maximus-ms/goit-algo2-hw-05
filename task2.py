import time
import mmh3
import math
from typing import List, Set
import re
import os
import sys
import json


class HyperLogLog:
    def __init__(self, precision: int = 14):
        """
        Initialize HyperLogLog with given precision.
        
        Args:
            precision (int): Precision parameter (number of registers = 2^precision)
        """
        self.precision = precision
        self.num_registers = 2 ** precision
        self.registers = [0] * self.num_registers
        self.alpha = self._get_alpha()

    def _get_alpha(self) -> float:
        """Get the alpha constant based on precision."""
        if self.precision == 4:
            return 0.673
        elif self.precision == 5:
            return 0.697
        elif self.precision == 6:
            return 0.709
        else:
            return 0.7213 / (1 + 1.079 / self.num_registers)

    def _get_register_index(self, hash_value: int) -> int:
        """Get register index from hash value."""
        return hash_value & (self.num_registers - 1)

    def _get_leading_zeros(self, hash_value: int) -> int:
        """Count leading zeros in hash value."""
        return bin(hash_value)[2:].zfill(32).find('1') + 1

    def add(self, item: str) -> None:
        """Add an item to the HyperLogLog."""
        hash_value = mmh3.hash(item)
        register_index = self._get_register_index(hash_value)
        leading_zeros = self._get_leading_zeros(hash_value)
        self.registers[register_index] = max(self.registers[register_index], leading_zeros)

    def count(self) -> int:
        """Get the estimated count of unique items."""
        harmonic_mean = sum(2 ** -register for register in self.registers)
        estimate = self.alpha * self.num_registers ** 2 / harmonic_mean

        # Apply small range correction
        if estimate < 2.5 * self.num_registers:
            zeros = self.registers.count(0)
            if zeros != 0:
                estimate = self.num_registers * math.log(self.num_registers / zeros)

        return int(estimate)

    def get_memory_usage(self) -> int:
        """Calculate actual memory usage of the HyperLogLog structure."""
        # Size of registers array (each register is a byte)
        registers_size = len(self.registers)
        # Size of other attributes
        other_size = sys.getsizeof(self.precision) + sys.getsizeof(self.num_registers) + sys.getsizeof(self.alpha)
        return registers_size + other_size


def extract_ip(line: str) -> str:
    """Extract IP address from a log line."""
    try:
        # Parse JSON properly
        data = json.loads(line)
        ip = data.get("remote_addr")
        # Also check http_x_forwarded_for for proxy IPs
        forwarded_for = data.get("http_x_forwarded_for")
        if forwarded_for:
            # Get the original client IP (first in the chain)
            ip = forwarded_for.split(',')[0].strip()
        
        if ip and all(0 <= int(part) <= 255 for part in ip.split('.')):
            return ip
    except json.JSONDecodeError:
        # Fallback to regex if JSON parsing fails
        pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        match = re.search(pattern, line)
        if match:
            ip = match.group(0)
            if all(0 <= int(part) <= 255 for part in ip.split('.')):           
                return ip
    except Exception as e:
        print(f"Error processing line: {e}")
    return None


def read_log_file(file_path: str, encoding: str = 'utf-8') -> List[str]:
    """Read log file with specified encoding."""
    try:
        with open(file_path, 'r', encoding=encoding) as f:
            lines = f.readlines()
            print(f"Successfully read {len(lines)} lines from the log file")
            return lines
    except UnicodeDecodeError:
        # Try different encodings if utf-8 fails
        encodings = ['latin1', 'cp1252', 'iso-8859-1']
        for enc in encodings:
            try:
                with open(file_path, 'r', encoding=enc) as f:
                    lines = f.readlines()
                    print(f"Successfully read {len(lines)} lines using {enc} encoding")
                    return lines
            except UnicodeDecodeError:
                continue
        raise ValueError(f"Could not read file with any of the encodings: {encodings}")


def exact_count_ips(log_file: str) -> Set[str]:
    """Count unique IPs using exact counting (set)."""
    unique_ips = set()
    processed_lines = 0
    error_lines = 0
    
    try:
        lines = read_log_file(log_file)
        total_lines = len(lines)
        
        for line in lines:
            processed_lines += 1
            ip = extract_ip(line)
            if ip:
                unique_ips.add(ip)
            else:
                error_lines += 1
            
            if processed_lines % 10000 == 0:
                print(f"Processed {processed_lines}/{total_lines} lines. Found {len(unique_ips)} unique IPs")
        
        print(f"\nProcessing complete:")
        print(f"Total lines: {total_lines}")
        print(f"Successfully processed: {processed_lines}")
        print(f"Lines with errors: {error_lines}")
        print(f"Unique IPs found: {len(unique_ips)}")
        
    except Exception as e:
        print(f"Error reading log file: {e}")
        return set()
    return unique_ips


def hyperloglog_count_ips(log_file: str, precision: int = 14) -> tuple[int, HyperLogLog]:
    """Count unique IPs using HyperLogLog."""
    hll = HyperLogLog(precision)
    processed_lines = 0
    error_lines = 0
    
    try:
        lines = read_log_file(log_file)
        total_lines = len(lines)
        
        for line in lines:
            processed_lines += 1
            ip = extract_ip(line)
            if ip:
                hll.add(ip)
            else:
                error_lines += 1
            
            if processed_lines % 10000 == 0:
                print(f"Processed {processed_lines}/{total_lines} lines")
                
        print(f"\nProcessing complete:")
        print(f"Total lines: {total_lines}")
        print(f"Successfully processed: {processed_lines}")
        print(f"Lines with errors: {error_lines}")
        
    except Exception as e:
        print(f"Error reading log file: {e}")
        return 0, hll
    return hll.count(), hll


def compare_methods(log_file: str):
    """Compare exact counting and HyperLogLog methods."""
    if not os.path.exists(log_file):
        print(f"Error: Log file '{log_file}' not found.")
        return

    # Exact counting
    print("\nStarting exact counting...")
    start_time = time.time()
    exact_ips = exact_count_ips(log_file)
    exact_time = time.time() - start_time
    exact_count = len(exact_ips)
    
    if exact_count == 0:
        print("No IP addresses found in the log file.")
        return
    
    # HyperLogLog counting
    print("\nStarting HyperLogLog counting...")
    start_time = time.time()
    hll_count, _ = hyperloglog_count_ips(log_file)
    hll_time = time.time() - start_time
    
    # Print results in tabular format
    print("\nРезультати порівняння:")
    print(f"{'':25} {'Точний підрахунок':>15} {'HyperLogLog':>15}")
    print(f"{'Унікальні елементи':25} {exact_count:>15.1f} {hll_count:>15.1f}")
    print(f"{'Час виконання (сек.)':25} {exact_time:>15.2f} {hll_time:>15.2f}")

if __name__ == "__main__":
    log_file = "lms-stage-access.log"
    compare_methods(log_file)
