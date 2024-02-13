#include <fstream>
#include <iostream>
#include <random>
#include <set>

std::string GenerateMnemonic(int wordCount) {
    std::ifstream file("wordlist.txt");
    std::string *bip39_words = new std::string[2048];
    std::string SingleMnemonic;
    int j = 0;
    while (std::getline(file, SingleMnemonic)) {
        bip39_words[j] = SingleMnemonic;
        j++;
    }

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 2047);

    std::set<int> used_indices;
    std::string mnemonic = "";

    for(int i = 0; i < wordCount; ++i) {
        int index;
        do {
            index = dis(gen);
        } while (used_indices.find(index) != used_indices.end());

        used_indices.insert(index);
        mnemonic += bip39_words[index] + " ";
    }

    return mnemonic;
}