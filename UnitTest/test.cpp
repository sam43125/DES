#include "catch.hpp"
#define NO_MAIN
#include "../DES/DES.cpp"
#include <random>
#include <functional>

TEST_CASE("Simple test") {
    DES obj(0x5B5A57676A56676EULL);
    REQUIRE(obj.Encrypt(0x675A69675E5A6B5AULL).to_ullong() == 0x974AFFBF86022D1FULL);
    REQUIRE(obj.Decrypt(0x974AFFBF86022D1FULL).to_ullong() == 0x675A69675E5A6B5AULL);
}

TEST_CASE("Test Encrypt and Decrypt", "[Encyrpt][Decrypt]") {

    ifstream fin("../DES/DES-Key-Plaintext.txt");
    ifstream answer("answer.txt");
    string keyText, plainText, cipherText, ansText;

    while (fin >> keyText >> plainText) {
        unsigned long long key, plain, ans;
        answer >> ansText;
        istringstream a(keyText), b(plainText), c(ansText);
        a >> hex >> key;
        b >> hex >> plain;
        c >> hex >> ans;
        auto cipher = DES(bitset<64>(key)).Encrypt(bitset<64>(plain));
        REQUIRE(cipher.to_ullong() == ans);
    }
    fin.close();

    fin.open("../DES/DES-Key-Ciphertext.txt");
    while (fin >> keyText >> cipherText) {
        unsigned long long key, cipher, ans;
        answer >> ansText;
        istringstream a(keyText), b(cipherText), c(ansText);
        a >> hex >> key;
        b >> hex >> cipher;
        c >> hex >> ans;
        auto plain = DES(bitset<64>(key)).Decrypt(bitset<64>(cipher));
        REQUIRE(plain.to_ullong() == ans);
    }

    fin.close();
    answer.close();
}

TEST_CASE("Random tests", "[Random]") {
    random_device rd;
    mt19937_64 eng(rd());
    uniform_int_distribution<unsigned long long> distr;
    auto rand = bind(distr, eng);
    for (int n = 0; n < 10; n++) {
        DES obj(rand());
        auto data = rand();
        REQUIRE(data == obj.Decrypt(obj.Encrypt(data)).to_ullong());
        REQUIRE(data == obj.Encrypt(obj.Decrypt(data)).to_ullong());
    }
}