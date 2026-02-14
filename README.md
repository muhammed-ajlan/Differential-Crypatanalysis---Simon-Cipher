# Differential Cryptanalysis of Simon Cipher

![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)
![Cryptography](https://img.shields.io/badge/category-cryptanalysis-red)

This project explores the vulnerability of the **Simon block cipher** (a lightweight block cipher designed by the NSA) to **Differential Cryptanalysis**. It specifically implements an attack on a simplified version of the cipher to demonstrate how statistical differences in input pairs can be used to recover key bits.

## 📖 Introduction

Differential cryptanalysis is a chosen-plaintext attack that observes how specific differences in plaintext pairs result in specific differences in the resulting ciphertexts. For the Simon cipher, which utilizes bitwise AND, XOR, and circular shifts, this project tracks the "differential characteristics" through multiple rounds.



## 📂 Project Structure

* `code.py` - The primary Python implementation containing the Simon cipher logic, differential characteristic generation, and the key recovery attack.
* `graphs&flows/` - Contains flowcharts and graphical representations of the differential paths and the cipher's round function.

## 🛠️ Features

* **Simon Cipher Implementation:** A functional version of the Simon block cipher (simplified parameters).
* **Differential Path Tracking:** Logic to calculate the probability of specific differential transitions.
* **Key Recovery:** Implementation of the attack algorithm to deduce the subkeys used in the final rounds.

## 🚀 Getting Started

### Prerequisites
You only need a standard Python 3 environment. No external libraries are strictly required for the core logic.

### Installation
```bash
git clone [https://github.com/muhammed-ajlan/Differential-Crypatanalysis---Simon-Cipher.git](https://github.com/muhammed-ajlan/Differential-Crypatanalysis---Simon-Cipher.git)
cd Differential-Crypatanalysis---Simon-Cipher
