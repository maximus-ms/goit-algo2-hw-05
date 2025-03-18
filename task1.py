import mmh3

class BloomFilter:
    def __init__(self, size: int, num_hashes: int):
        self.size = size
        self.num_hashes = num_hashes
        self.bit_array = bytearray([0] * size)
        self.allowed_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?')

    def _get_hash_value(self, item: str, seed: int):
        return mmh3.hash(item, seed) % self.size

    def _validate_password(self, password: str) -> None:
        if not isinstance(password, str):
            raise TypeError("BloomFilter only accepts string items")
            
        unexpected_chars = set(password) - self.allowed_chars
        if unexpected_chars:
            raise ValueError(f"Password contains unexpected symbols: {unexpected_chars}")

    def add(self, item: str):
        self._validate_password(item)
            
        for seed in range(self.num_hashes):
            self.bit_array[self._get_hash_value(item, seed)] = 1

    def check(self, item: str):
        self._validate_password(item)
            
        for seed in range(self.num_hashes):
            if not self.bit_array[self._get_hash_value(item, seed)]:
                return False
        return True


def check_password_uniqueness(bloom, passwords):
    results = {}
    for password in passwords:
        if bloom.check(password):
            results[password] = "вже використаний"
        else:
            results[password] = "унікальний"
    return results


if __name__ == "__main__":
    # Ініціалізація фільтра Блума
    bloom = BloomFilter(size=1000, num_hashes=3)

    # Додавання існуючих паролів
    existing_passwords = ["password123", "admin123", "qwerty123"]
    for password in existing_passwords:
        bloom.add(password)

    # Перевірка нових паролів
    new_passwords_to_check = ["password123", "newpassword", "admin123", "guest"]
    results = check_password_uniqueness(bloom, new_passwords_to_check)

    # Виведення результатів
    for password, status in results.items():
        print(f"Пароль '{password}' - {status}.")
