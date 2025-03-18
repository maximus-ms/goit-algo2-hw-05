# Algo2. Home work 5
## "Algorithms to Work with Big Data"

### Task 1. Password Uniqueness Checking Using Bloom Filter

Create a function to check password uniqueness using a Bloom Filter. This function should determine whether a password has been used before, without the need to store the actual passwords.

#### Technical Requirements

1. Implement a `BloomFilter` class that provides functionality to add elements to the filter and check for element presence in the filter.

2. Implement a `check_password_uniqueness` function that uses a `BloomFilter` instance to check a list of new passwords for uniqueness. It should return the check result for each password.

3. Ensure proper handling of all data types. Passwords should be processed simply as strings, without hashing. Empty or invalid values should also be considered and handled appropriately.

4. The function and class should work with large datasets while using minimal memory.

#### Acceptance Criteria

1. The `BloomFilter` class implements the Bloom filter logic.

2. The `check_password_uniqueness` function checks new passwords using the provided filter.

3. The code includes a usage example according to expected results.


#### Solution is implemented in file task1.py

Results
```
Пароль 'password123' - вже використаний.
Пароль 'newpassword' - унікальний.
Пароль 'admin123' - вже використаний.
Пароль 'guest' - унікальний.
```


### Task 2. Performance Comparison of HyperLogLog with Exact Unique Element Counting

Create a script to compare exact counting of unique elements with counting using HyperLogLog.

#### Technical Requirements

1. Load a dataset from a real log file [lms-stage-access.log](https://drive.google.com/file/d/13NUCSG7l_z2B7gYuQubYIpIjJTnwOAOb/view?usp=sharing) containing IP address information.

2. Implement a method for exact counting of unique IP addresses using the set structure.

3. Implement a method for approximate counting of unique IP addresses using HyperLogLog.

4. Compare the methods by execution time.

#### Acceptance Criteria

1. The data loading method processes the log file, ignoring incorrect lines.

2. The exact counting function returns the correct number of unique IP addresses.

3. HyperLogLog shows results with acceptable error.

4. Comparison results are presented in table format.

5. The code is adapted for large datasets.


#### Solution is implemented in file task2.py

Results
```
Результати порівняння:
                          Точний підрахунок     HyperLogLog
Унікальні елементи                   28.0            28.0
Час виконання (сек.)                 0.76            0.49
```
