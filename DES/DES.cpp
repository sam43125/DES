// Compile with -std=c++17 (gcc7) or MSVC
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <string>
#include <bitset>
#include <ctime>
using namespace std;
using table = unsigned char;

class DES {
public:
    DES(const bitset<64>& key) {
        // Key scheduling
        bitset<28> left, right;
        for (size_t i = 0; i < 28; i++) {
            left[27 - i] = key[64 - PC1L[i]];
            right[27 - i] = key[64 - PC1R[i]];
        }
        for (size_t i = 0; i < 16; i++) {
            LShift(left, LSCount[i]);
            LShift(right, LSCount[i]);
            bitset<56> all(left.to_string() + right.to_string());
            for (size_t j = 0; j < 48; j++)
                subkeys[i][47 - j] = all[56 - PC2[j]];
        }
    }

    ~DES() = default;

    bitset<64> Encrypt(const bitset<64>& plain) const {
        // Initial permutation
        bitset<32> left, right;
        for (size_t i = 0; i < 32; i++) {
            left[31 - i] = plain[64 - IP[i]];
            right[31 - i] = plain[64 - IP[i + 32]];
        }
        // Process
        for (size_t i = 0; i < 16; i++) {
            left ^= fnF(right, subkeys[i]);
            swap(left, right);
        }
        // Final permutation
        bitset<64> cipher;
        bitset<64> all(right.to_string() + left.to_string());
        for (size_t i = 0; i < 64; i++)
            cipher[63 - i] = all[64 - FP[i]];
        return cipher;
    }

    bitset<64> Decrypt(const bitset<64>& cipher) const {
        // Initial permutation
        bitset<32> left, right;
        for (size_t i = 0; i < 32; i++) {
            left[31 - i] = cipher[64 - IP[i]];
            right[31 - i] = cipher[64 - IP[i + 32]];
        }
        // Process
        for (size_t i = 0; i < 16; i++) {
            left ^= fnF(right, subkeys[15 - i]);
            swap(left, right);
        }
        // Final permutation
        bitset<64> plain;
        bitset<64> all(right.to_string() + left.to_string());
        for (size_t i = 0; i < 64; i++)
            plain[63 - i] = all[64 - FP[i]];
        return plain;
    }

private:

    bitset<32> fnF(const bitset<32>& R, const bitset<48>& subkey) const {
        // Feistel (F) function
        bitset<48> S_in = fnE(R) ^ subkey;
        string temp;
        for (size_t i = 0; i < 8; i++)
            temp += fnS(bitset<6>(S_in.to_string().substr(i * 6, 6)), i).to_string();
        bitset<32> S_out(temp);
        bitset<32> result = fnP(S_out);
        return result;
    }

    bitset<48> fnE(const bitset<32>& R) const {
        // Expansion function
        bitset<48> result;
        for (size_t i = 0; i < 48; i++)
            result[47 - i] = R[32 - E[i]];
        return result;
    }

    bitset<4> fnS(const bitset<6>& Si, size_t i) const {
        // Substitution (S-Box)
        string bits = Si.to_string();
        int j = stoi(string{ bits[0], bits[5] }, nullptr, 2);
        int k = stoi(bits.substr(1, 4), nullptr, 2);
        bitset<4> result(S_box[i][j * 16 + k]);
        return result;
    }

    bitset<32> fnP(const bitset<32>& R) const {
        // Permutation
        bitset<32> result;
        for (size_t i = 0; i < 32; i++)
            result[31 - i] = R[32 - P[i]];
        return result;
    }

    inline void LShift(bitset<28>& key, size_t count) {
        key = (key << count) | (key >> (28 - count));
    }

    bitset<48> subkeys[16];

    static constexpr table IP[] = { 58, 50, 42, 34, 26, 18, 10, 2,
                                    60, 52, 44, 36, 28, 20, 12, 4,
                                    62, 54, 46, 38, 30, 22, 14, 6,
                                    64, 56, 48, 40, 32, 24, 16, 8,
                                    57, 49, 41, 33, 25, 17,  9, 1,
                                    59, 51, 43, 35, 27, 19, 11, 3,
                                    61, 53, 45, 37, 29, 21, 13, 5,
                                    63, 55, 47, 39, 31, 23, 15, 7,
                                  };

    static constexpr table FP[] = { 40, 8, 48, 16, 56, 24, 64, 32,
                                    39, 7, 47, 15, 55, 23, 63, 31,
                                    38, 6, 46, 14, 54, 22, 62, 30,
                                    37, 5, 45, 13, 53, 21, 61, 29,
                                    36, 4, 44, 12, 52, 20, 60, 28,
                                    35, 3, 43, 11, 51, 19, 59, 27,
                                    34, 2, 42, 10, 50, 18, 58, 26,
                                    33, 1, 41,  9, 49, 17, 57, 25,
                                  };

    static constexpr table E[] = {  32,  1,  2,  3,  4,  5,
                                     4,  5,  6,  7,  8,  9,
                                     8,  9, 10, 11, 12, 13,
                                    12, 13, 14, 15, 16, 17,
                                    16, 17, 18, 19, 20, 21,
                                    20, 21, 22, 23, 24, 25,
                                    24, 25, 26, 27, 28, 29,
                                    28, 29, 30, 31, 32,  1
                                 };

    static constexpr table P[] = {  16,  7, 20, 21,
                                    29, 12, 28, 17,
                                     1, 15, 23, 26,
                                     5, 18, 31, 10,
                                     2,  8, 24, 14,
                                    32, 27,  3,  9,
                                    19, 13, 30,  6,
                                    22, 11,  4, 25
                                 };

    static constexpr table PC1L[] = { 57, 49, 41, 33, 25, 17,  9, 
                                       1, 58, 50, 42, 34, 26, 18,
                                      10,  2, 59, 51, 43, 35, 27,
                                      19, 11,  3, 60, 52, 44, 36,
                                    };

    static constexpr table PC1R[] = { 63, 55, 47, 39, 31, 23, 15,
                                       7, 62, 54, 46, 38, 30, 22,
                                      14,  6, 61, 53, 45, 37, 29,
                                      21, 13,  5, 28, 20, 12,  4
                                    };

    static constexpr table PC2[] = { 14, 17, 11, 24,  1,  5,
                                      3, 28, 15,  6, 21, 10,
                                     23, 19, 12,  4, 26,  8,
                                     16,  7, 27, 20, 13,  2,
                                     41, 52, 31, 37, 47, 55,
                                     30, 40, 51, 45, 33, 48,
                                     44, 49, 39, 56, 34, 53,
                                     46, 42, 50, 36, 29, 32
                                   };

    static constexpr table S_box[8][64] = { {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
                                            0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
                                            4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
                                            15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13},

                                            {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
                                            3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
                                            0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
                                            13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9},

                                            {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
                                            13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
                                            13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
                                            1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12},

                                            {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
                                            13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
                                            10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
                                            3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14},

                                            {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
                                            14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
                                            4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
                                            11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3},

                                            {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
                                            10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
                                            9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
                                            4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13},

                                            {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
                                            13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
                                            1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
                                            6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12},

                                            {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
                                            1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
                                            7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
                                            2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11} 
                                          };

    static constexpr size_t LSCount[] = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

};

void encrypt(ofstream& fout) {

    ifstream fin("DES-Key-Plaintext.txt");
    string keyText, plainText;

    while (fin >> keyText >> plainText){
        unsigned long long key, plain;
        istringstream a(keyText), b(plainText);
        a >> hex >> key;
        b >> hex >> plain;
        auto cipher = DES(bitset<64>(key)).Encrypt(bitset<64>(plain));
        fout << setfill('0') << setw(16) << hex << cipher.to_ullong() << endl;
    }

    fin.close();
}

void decrypt(ofstream& fout) {

    ifstream fin("DES-Key-Ciphertext.txt");
    string keyText, cipherText;

    while (fin >> keyText >> cipherText) {
        unsigned long long key, cipher;
        istringstream a(keyText), b(cipherText);
        a >> hex >> key;
        b >> hex >> cipher;
        auto plain = DES(bitset<64>(key)).Decrypt(bitset<64>(cipher));
        fout << setfill('0') << setw(16) << hex << plain.to_ullong() << endl;
    }

    fin.close();
}

#ifndef NO_MAIN

int main() {

    clock_t start, end;
    double cpu_time_used;
    start = clock();

    ofstream fout("out.txt");

    encrypt(fout);
    decrypt(fout);

    end = clock();
    cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC / 20;
    fout << cpu_time_used * 1000 << " ms";
    fout.close();
    return 0;
}

#endif
