//
// Created by YonezawaYukari on 2022/10/30.
//

#include "aes.h"

std::string aes::decrypt(const std::string &msg, std::string key, int nBits) {
    int blockSize = 16;
    if (!(nBits == 128 || nBits == 192 || nBits == 256)) return "";
    std::vector<Byte> msg_text = base64_decode(msg);
    std::string ciphertext(msg_text.begin(), msg_text.end());
    int nBytes = nBits / 8;
    std::vector<Byte> pwdBytes;
    for (int i = 0; i < nBytes; i++) {
        if (i < key.size())
            pwdBytes.push_back((Byte) key[i] & 0xff);
        else
            pwdBytes.push_back(0);
    }
    std::vector<Byte> nkey_16 = this->cipher(pwdBytes, this->keyExpansion(pwdBytes));
    for (int i = 0; i < nBytes - 16; i++) {
        nkey_16.push_back(nkey_16[i]);
    }
    std::array<char, 8> ctrTxt{};
    for (int i = 0; i < 8; i++)
        ctrTxt[i] = msg_text[i];
    std::vector<Byte> counter(16);
    std::vector<std::array<Byte, 4>> keySchedule = this->keyExpansion(nkey_16);
    for (int i = 0; i < 8; i++) {
        counter[i] = ctrTxt[i];
    }
    float nBlocks = ceil((float) (msg_text.size() - 8) / blockSize);
    std::vector<std::string> ct(nBlocks);
    for (int b = 0; b < nBlocks; b++) {
        ct[b] = ciphertext.substr(b * blockSize + 8, 16);
    }
    std::vector<Byte> plainByte;
    for (int i = 0; i < nBlocks; i++) {
        for (int c = 0; c < 4; c++)
            counter[15 - c] = (Byte) (unsigned(i) >> c * 8) & 0xff;
        auto cipherCntr = this->cipher(counter, keySchedule);
        for (int k = 0; k < ct[i].size(); k++) {
            plainByte.push_back(cipherCntr[k] ^ ct[i][k]);
        }
    }
    return {plainByte.begin(), plainByte.end()};
}

std::vector<Byte> aes::cipher(std::vector<Byte> input, const std::vector<std::array<Byte, 4> > &keySchedule) {
    int Nb = 4;
    int Nr = keySchedule.size() / Nb - 1;
    std::array<std::array<Byte, 4>, 4> state{};
    for (int i = 0; i < 4 * Nb; i++)
        state[i % 4][floor(i / 4)] = input[i];
    state = aes::addRoundKey(state, keySchedule, 0, Nb);
    for (int round = 1; round < Nr; round++) {
        state = this->subBytes(state, Nb);
        state = aes::shiftRows(state, Nb);
        state = aes::mixColumns(state, Nb);
        state = aes::addRoundKey(state, keySchedule, round, Nb);
    }
    state = this->subBytes(state, Nb);
    state = aes::shiftRows(state, Nb);
    state = aes::addRoundKey(state, keySchedule, Nr, Nb);
    std::vector<Byte> output(4 * Nb);
    for (int i = 0; i < 4 * Nb; i++)
        output[i] = state[i % 4][floor(i / 4)];
    return output;
}

std::vector<std::array<Byte, 4>> aes::keyExpansion(std::vector<Byte> key) {
    int Nb = 4;
    int Nk = key.size() / 4;
    int Nr = Nk + 6;
    std::vector<std::array<Byte, 4>> w((Nb * (Nr + 1)));
    std::array<Byte, 4> temp{};

    for (int i = 0; i < Nk; i++) {
        for (int k = 0; k < 4; k++)
            w[i][k] = key[i * 4 + k];
    }

    for (int i = Nk; i < (Nb * (Nr + 1)); i++) {
        w[i] = std::array<Byte, 4>{};
        for (int t = 0; t < 4; t++)
            temp[t] = w[i - 1][t];
        if (i % Nk == 0) {
            temp = rotWord(temp);
            temp = subWord(temp);
            for (int t = 0; t < 4; t++)
                temp[t] ^= this->rCon[i / Nk][t];
        } else if (Nk > 6 && i % Nk == 4) {
            temp = subWord(temp);
        }
        for (int t = 0; t < 4; t++)
            w[i][t] = w[i - Nk][t] ^ temp[t];
    }
    return w;
}

std::array<Byte, 4> aes::rotWord(std::array<Byte, 4> temp) {
    char tmp = temp[0];
    for (int i = 0; i < 3; i++)
        temp[i] = temp[i + 1];
    temp[3] = tmp;
    return temp;
}

std::array<Byte, 4> aes::subWord(std::array<Byte, 4> temp) {
    for (int i = 0; i < 4; i++)
        temp[i] = this->sBox[temp[i]];
    return temp;
}

std::string aes::encrypt(const std::string &msg, std::string key, int nBits, bool keep) {
    int blockSize = 16;
    if (!(nBits == 128 || nBits == 192 || nBits == 256)) return "";
    int nBytes = nBits / 8;
    std::vector<Byte> pwdBytes;
    for (int i = 0; i < nBytes; i++) {
        if (i < key.size())
            pwdBytes.push_back((Byte) key[i] & 0xff);
        else
            pwdBytes.push_back(0);
    }
    std::vector<Byte> nkey_16 = this->cipher(pwdBytes, this->keyExpansion(pwdBytes));
    for (int i = 0; i < nBytes - 16; i++) {
        nkey_16.push_back(nkey_16[i]);
    }

    std::vector<Byte> counter(16);
    float nonceMs, nonceSec, nonceRnd = 0;
    if (keep) {
        float nonce = 10000;
        nonceMs = fmod(nonce, 1000);
        nonceSec = floor(nonce / 1000);
        nonceRnd = 10000;
    } else {
        float nonce = floor((double(std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count()) / double(1000000)) * 1000);
        nonceMs = fmod(nonce, 1000);
        nonceSec = floor(nonce / 1000);
        srand(time(0));
        nonceRnd = floor((rand() % (0xffff + 1)));
    }
    for (int i = 0; i < 2; i++) {
        counter[i] = (Byte) (unsigned(nonceMs) >> i * 8) & 0xff;
        counter[i + 2] = (Byte) (unsigned(nonceRnd) >> i * 8) & 0xff;
    }

    for (int i = 0; i < 4; i++)
        counter[i + 4] = (Byte) (unsigned(nonceSec) >> i * 8) & 0xff;
    std::array<char, 8> ctrTxt{};
    for (int i = 0; i < 8; i++)
        ctrTxt[i] = counter[i];
    std::vector<std::array<Byte, 4>> keySchedule = this->keyExpansion(nkey_16);
    float blockCount = ceil(float(msg.size()) / float(blockSize));
    std::string ct;
    for (int b = 0; b < blockCount; b++) {
        for (int c = 0; c < 4; c++) {
            counter[15 - c] = (Byte) (unsigned(b) >> c * 8) & 0xff;
            counter[15 - c - 4] = (Byte) (unsigned(b / 0x100000000) >> c * 8);
        }
        std::vector<Byte> cipherCntr = this->cipher(counter, keySchedule);
        int blockLength = b < blockCount - 1 ? blockSize : (msg.size() - 1) % blockSize + 1;
        for (int i = 0; i < blockLength; i++) {
            ct += (char) (msg[b * blockSize + i] ^ cipherCntr[i]);
        }
    }
    std::vector<Byte> ciphertext(ctrTxt.begin(), ctrTxt.end());
    for (char i: ct)
        ciphertext.push_back(i);
    return base64_encode(ciphertext.data(), ciphertext.size());
}
