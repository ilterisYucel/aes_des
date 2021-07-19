#include "AES.h"

AES::AES(int keyLen)
{
  this->Nb = 4;
  switch (keyLen)
  {
  case 128:
    this->Nk = 4;
    this->Nr = 10;
    break;
  case 192:
    this->Nk = 6;
    this->Nr = 12;
    break;
  case 256:
    this->Nk = 8;
    this->Nr = 14;
    break;
  default:
    throw "Incorrect key length";
  }

  blockBytesLen = 4 * this->Nb * sizeof(unsigned char);
}

unsigned char * AES::EncryptECB(unsigned char in[], unsigned int inLen, unsigned  char key[], unsigned int &outLen)
{
  outLen = GetPaddingLength(inLen);
  unsigned char *alignIn  = PaddingNulls(in, inLen, outLen);
  unsigned char *out = new unsigned char[outLen];
  for (unsigned int i = 0; i < outLen; i+= blockBytesLen)
  {
    EncryptBlock(alignIn + i, out + i, key);
  }
  
  delete[] alignIn;
  
  return out;
}

unsigned char * AES::DecryptECB(unsigned char in[], unsigned int inLen, unsigned  char key[])
{
  unsigned char *out = new unsigned char[inLen];
  for (unsigned int i = 0; i < inLen; i+= blockBytesLen)
  {
    DecryptBlock(in + i, out + i, key);
  }
  
  return out;
}


unsigned char *AES::EncryptCBC(unsigned char in[], unsigned int inLen, unsigned  char key[], unsigned char * iv, unsigned int &outLen)
{
  outLen = GetPaddingLength(inLen);
  unsigned char *alignIn  = PaddingNulls(in, inLen, outLen);
  unsigned char *out = new unsigned char[outLen];
  unsigned char *block = new unsigned char[blockBytesLen];
  memcpy(block, iv, blockBytesLen);
  for (unsigned int i = 0; i < outLen; i+= blockBytesLen)
  {
    XorBlocks(block, alignIn + i, block, blockBytesLen);
    EncryptBlock(block, out + i, key);
    memcpy(block, out + i, blockBytesLen);
  }
  
  delete[] block;
  delete[] alignIn;

  return out;
}

unsigned char *AES::DecryptCBC(unsigned char in[], unsigned int inLen, unsigned  char key[], unsigned char * iv)
{
  unsigned char *out = new unsigned char[inLen];
  unsigned char *block = new unsigned char[blockBytesLen];
  memcpy(block, iv, blockBytesLen);
  for (unsigned int i = 0; i < inLen; i+= blockBytesLen)
  {
    DecryptBlock(in + i, out + i, key);
    XorBlocks(block, out + i, out + i, blockBytesLen);
    memcpy(block, in + i, blockBytesLen);
  }
  
  delete[] block;

  return out;
}

unsigned char *AES::EncryptCTR(unsigned char in[], unsigned int inLen, unsigned  char key[], unsigned char * iv, unsigned int &outLen, unsigned long int nonce)
{
  outLen = GetPaddingLength(inLen);
  unsigned char *alignIn  = PaddingNulls(in, inLen, outLen);
  unsigned char *out = new unsigned char[outLen];
  unsigned char *block = new unsigned char[blockBytesLen];
  unsigned char *np = new unsigned char[blockBytesLen];
  for (unsigned int i = 0; i < outLen; i+= blockBytesLen)
  {
    *(np+(blockBytesLen-4)) = (nonce+i);
    memcpy(block, iv, blockBytesLen);
    XorBlocks(block, np, block, blockBytesLen);
    EncryptBlock(block, block, key);
    XorBlocks(block,alignIn + i, out + i, blockBytesLen);
  }
  
  delete[] block;
  delete[] alignIn;

  return out;
}

unsigned char *AES::DecryptCTR(unsigned char in[], unsigned int inLen, unsigned  char key[], unsigned char * iv, unsigned long int nonce)
{
  unsigned char *out = new unsigned char[inLen];
  unsigned char *block = new unsigned char[blockBytesLen];
  unsigned char *np = new unsigned char[blockBytesLen];
  for (unsigned int i = 0; i < inLen; i+= blockBytesLen)
  {
    *(np+(blockBytesLen-4)) = (nonce+i);
    memcpy(block, iv, blockBytesLen);
    XorBlocks(block, np, block, blockBytesLen);
    EncryptBlock(block, block, key);
    XorBlocks(block,in + i, out + i, blockBytesLen);
  }
  
  delete[] block;

  return out;
}

unsigned char *AES::EncryptOFB(unsigned char in[], unsigned int inLen, unsigned  char key[], unsigned char * iv, unsigned int &outLen)
{
  outLen = GetPaddingLength(inLen);
  unsigned char *alignIn  = PaddingNulls(in, inLen, outLen);
  unsigned char *out = new unsigned char[outLen];
  unsigned char *block = new unsigned char[blockBytesLen];
  memcpy(block, iv, blockBytesLen);
  for (unsigned int i = 0; i < outLen; i+= blockBytesLen)
  {
    XorBlocks(block,alignIn + i, out + i, blockBytesLen);
    EncryptBlock(block, block, key);
  }
  
  delete[] block;
  delete[] alignIn;

  return out;
}

unsigned char *AES::DecryptOFB(unsigned char in[], unsigned int inLen, unsigned  char key[], unsigned char * iv)
{
  unsigned char *out = new unsigned char[inLen];
  unsigned char *block = new unsigned char[blockBytesLen];
  memcpy(block, iv, blockBytesLen);
  for (unsigned int i = 0; i < inLen; i+= blockBytesLen)
  {
    XorBlocks(block,in + i, out + i, blockBytesLen);
    EncryptBlock(block, block, key);
  }
  
  delete[] block;

  return out;
}

unsigned char *AES::EncryptDESCBC(unsigned char in[], unsigned int inLen, unsigned  char key[], unsigned char * iv, unsigned int &outLen)
{
  outLen = GetPaddingLength(inLen);
  unsigned char *alignIn  = PaddingNulls(in, inLen, outLen);
  unsigned char *out = new unsigned char[outLen];
  unsigned char *block = new unsigned char[8];
  memcpy(block, iv, blockBytesLen);
  for (unsigned int i = 0; i < outLen; i+= 8)
  {
    XorBlocks(block, alignIn + i, block, 8);
    encryptDES(block, out + i, key);
    memcpy(block, out + i, 8);
  }
  
  delete[] block;
  delete[] alignIn;

  return out;
}

unsigned char *AES::DecryptDESCBC(unsigned char in[], unsigned int inLen, unsigned  char key[], unsigned char * iv)
{
  unsigned char *out = new unsigned char[inLen];
  unsigned char *block = new unsigned char[8];
  memcpy(block, iv, blockBytesLen);
  for (unsigned int i = 0; i < inLen; i+= 8)
  {
    decryptDES(in + i, out + i, key);
    XorBlocks(block, out + i, out + i, 8);
    memcpy(block, in + i, 8);
  }
  
  delete[] block;

  return out;
}

unsigned char *AES::EncryptDESCTR(unsigned char in[], unsigned int inLen, unsigned  char key[], unsigned char * iv, unsigned int &outLen, unsigned long int nonce)
{
  outLen = GetPaddingLength(inLen);
  unsigned char *alignIn  = PaddingNulls(in, inLen, outLen);
  unsigned char *out = new unsigned char[outLen];
  unsigned char *block = new unsigned char[8];
  unsigned char *np = new unsigned char[8];
  for (unsigned int i = 0; i < outLen; i+= 8)
  {
    *(np+(blockBytesLen-4)) = (nonce+i);
    memcpy(block, iv, 8);
    XorBlocks(block, np, block, 8);
    encryptDES(block, block, key);
    XorBlocks(block,alignIn + i, out + i, 8);
  }
  
  delete[] block;
  delete[] alignIn;

  return out;
}

unsigned char *AES::DecryptDESCTR(unsigned char in[], unsigned int inLen, unsigned  char key[], unsigned char * iv, unsigned long int nonce)
{
  unsigned char *out = new unsigned char[inLen];
  unsigned char *block = new unsigned char[8];
  unsigned char *np = new unsigned char[8];
  for (unsigned int i = 0; i < inLen; i+= 8)
  {
    *(np+(blockBytesLen-4)) = (nonce+i);
    memcpy(block, iv, 8);
    XorBlocks(block, np, block, 8);
    encryptDES(block, block, key);
    XorBlocks(block,in + i, out + i, 8);
  }
  
  delete[] block;

  return out;
}

unsigned char *AES::EncryptDESOFB(unsigned char in[], unsigned int inLen, unsigned  char key[], unsigned char * iv, unsigned int &outLen)
{
  outLen = GetPaddingLength(inLen);
  unsigned char *alignIn  = PaddingNulls(in, inLen, outLen);
  unsigned char *out = new unsigned char[outLen];
  unsigned char *block = new unsigned char[8];
  memcpy(block, iv, blockBytesLen);
  for (unsigned int i = 0; i < outLen; i+= 8)
  {
    XorBlocks(block,alignIn + i, out + i, 8);
    encryptDES(block, block, key);
  }
  
  delete[] block;
  delete[] alignIn;

  return out;
}

unsigned char *AES::DecryptDESOFB(unsigned char in[], unsigned int inLen, unsigned  char key[], unsigned char * iv)
{
  unsigned char *out = new unsigned char[inLen];
  unsigned char *block = new unsigned char[8];
  memcpy(block, iv, blockBytesLen);
  for (unsigned int i = 0; i < inLen; i+= 8)
  {
    XorBlocks(block,in + i, out + i, 8);
    encryptDES(block, block, key);
  }
  
  delete[] block;

  return out;
}

unsigned char *AES::EncryptCFB(unsigned char in[], unsigned int inLen, unsigned  char key[], unsigned char * iv, unsigned int &outLen)
{
  outLen = GetPaddingLength(inLen);
  unsigned char *alignIn  = PaddingNulls(in, inLen, outLen);
  unsigned char *out = new unsigned char[outLen];
  unsigned char *block = new unsigned char[blockBytesLen];
  unsigned char *encryptedBlock = new unsigned char[blockBytesLen];
  memcpy(block, iv, blockBytesLen);
  for (unsigned int i = 0; i < outLen; i+= blockBytesLen)
  {
    EncryptBlock(block, encryptedBlock, key);
    XorBlocks(alignIn + i, encryptedBlock, out + i, blockBytesLen);
    memcpy(block, out + i, blockBytesLen);
  }
  
  delete[] block;
  delete[] encryptedBlock;
  delete[] alignIn;

  return out;
}

unsigned char *AES::DecryptCFB(unsigned char in[], unsigned int inLen, unsigned  char key[], unsigned char * iv)
{
  unsigned char *out = new unsigned char[inLen];
  unsigned char *block = new unsigned char[blockBytesLen];
  unsigned char *encryptedBlock = new unsigned char[blockBytesLen];
  memcpy(block, iv, blockBytesLen);
  for (unsigned int i = 0; i < inLen; i+= blockBytesLen)
  {
    EncryptBlock(block, encryptedBlock, key);
    XorBlocks(in + i, encryptedBlock, out + i, blockBytesLen);
    memcpy(block, in + i, blockBytesLen);
  }
  
  delete[] block;
  delete[] encryptedBlock;

  return out;
}

char* AES::BinaryAsHex(char * binary, int bit) {
  char* result = new char[16];
  
  int val = 0;
  for(int i =0;i<bit;i=i+8){
    val = 128*binary[i] + 64*binary[i+1] + 32*binary[i+2] + 16*binary[i+3] + 8*binary[i+4] + 4*binary[i+5] + 2*binary[i+6] + binary[i+7];
    sprintf(result+(i/4),"%02x",val);

  }
  return result;
}

char* AES::HexToHexAshesToAshes(char* in) {
    char* out = new char[17];
    sscanf(in,"%16s",out);
    return out;
}

void AES::encryptDES(unsigned char* in, unsigned char *out, unsigned char* keyS){
  char plainTextHexString[17];
  char keyHexString[17];
  
  for (int i = 0; i < 8; i++) {
      sprintf(plainTextHexString+(i*2),"%02x",in[i]);
      sprintf(keyHexString+(i*2),"%02x",keyS[i]);
  }
  plainTextHexString[16] = '\0';
  keyHexString[16] = '\0';

  char plainTextBlock[8];
  unsigned long plainTextHexValue = std::strtoul(plainTextHexString, 0, 16);
  memcpy(plainTextBlock,&plainTextHexValue,8);
  std::reverse(plainTextBlock, plainTextBlock+8);

  //setup key
  char key[8];
  unsigned long keyHexValue = std::strtoul(keyHexString, 0, 16);
  memcpy(key,&keyHexValue,8);
  std::reverse(key, key+8);

  char* ptbBinary = new char[64];
  char keyBinary[64];
  byteBlockToBinary(plainTextBlock,ptbBinary);
  byteBlockToBinary(key,keyBinary);

  char subkeysBinary[16][48];

  char CiDi[56];

  PC_1(keyBinary,CiDi);
  for(int round=1;round<=16;round++){
    LS(CiDi,round);
    PC_2(CiDi,subkeysBinary[round-1]);
  }

  IP(ptbBinary);

  for(int round=1;round<=16;round++){
    iterate(ptbBinary,subkeysBinary[round-1]);
  }

  swapLeftAndRight(ptbBinary,64);

  IP_REVERSE(ptbBinary);
  
  char* e = BinaryAsHex(ptbBinary,64);
  char tmp[3];
  tmp[3] = '\0';
  for (int i = 0; i < 16; i+=2) {
      memcpy(tmp, e+i, 2);
      out[i/2] = (unsigned char) strtoul(tmp,NULL, 16);
  }
}

void AES::decryptDES(unsigned char* in, unsigned char *out, unsigned char* keyS){
  char plainTextHexString[17];
  char keyHexString[17];
  
  for (int i = 0; i < 8; i++) {
      sprintf(plainTextHexString+(i*2),"%02x",in[i]);
      sprintf(keyHexString+(i*2),"%02x",keyS[i]);
  }
  plainTextHexString[16] = '\0';
  keyHexString[16] = '\0';

  char plainTextBlock[8];
  unsigned long plainTextHexValue = std::strtoul(plainTextHexString, 0, 16);
  memcpy(plainTextBlock,&plainTextHexValue,8);
  std::reverse(plainTextBlock, plainTextBlock+8);

  //setup key
  char key[8];
  unsigned long keyHexValue = std::strtoul(keyHexString, 0, 16);
  memcpy(key,&keyHexValue,8);
  std::reverse(key, key+8);

  char* ptbBinary = new char[64];
  char keyBinary[64];
  byteBlockToBinary(plainTextBlock,ptbBinary);
  byteBlockToBinary(key,keyBinary);

  char subkeysBinary[16][48];

  char CiDi[56];

  PC_1(keyBinary,CiDi);
  for(int round=1;round<=16;round++){
    LS(CiDi,round);
    PC_2(CiDi,subkeysBinary[round-1]);
  }

  IP(ptbBinary);

  for(int round=16;round>0;round--){
    iterate(ptbBinary,subkeysBinary[round-1]);
  }

  swapLeftAndRight(ptbBinary,64);

  IP_REVERSE(ptbBinary);


  char* e = BinaryAsHex(ptbBinary,64);
  char tmp[3];
  tmp[3] = '\0';
  for (int i = 0; i < 16; i+=2) {
      memcpy(tmp, e+i, 2);
      out[i/2] = (unsigned char) strtoul(tmp,NULL, 16);
  }
}

const char * AES::byte_to_binary(int x)
{
    static char b[9];
    b[0] = '\0';

    int z;
    for (z = 128; z > 0; z >>= 1){
      strcat(b, ((x & z) == z) ? "1" : "0");
    }

    return b;
}


void AES::byteBlockToBinary(char * byteBlock, char * res) {
  int j = 0;
  for(int i=0;i<8;i++){
    int byte = byteBlock[i];
    for(int x = 128; x>0; x>>= 1){
      //res[j] = ((byte & x) == x) ? '1':'0';
      res[j] = ((byte & x) == x) ? 1:0;
      j++;
    }

  }
}

void AES::IP(char * binaryBlock){
  char tempBlock[64];
  for(int i=0;i<64;i++){
    tempBlock[i] = binaryBlock[table_ip[i]-1];
  }
  memcpy(binaryBlock,tempBlock,64);
}

void AES::IP_REVERSE(char * binaryBlock){
  char tempBlock[64];
  for(int i=0;i<64;i++){
    tempBlock[i] = binaryBlock[table_ip_reverse[i]-1];
  }
  memcpy(binaryBlock,tempBlock,64);
}

void AES::PC_1(char * binaryBlock,char * C0D0){
  for(int i=0;i<56;i++){
    C0D0[i] = binaryBlock[table_pc_1[i]-1];
  }
}

void AES::LS(char * CiDi,int round){
  //i == round
  if(round == 1 || round == 2 || round == 9 || round == 16){
    char first;

    //LEFT - Ci
    first = CiDi[0];
    for(int i=0;i<27;i++){
      CiDi[i] = CiDi[i+1];
    }
    CiDi[27] = first;

    //RIGHT - Di
    first = CiDi[28];
    for(int i=28;i<55;i++){
      CiDi[i] = CiDi[i+1];
    }
    CiDi[55] = first;
  } else {
    char first;
    char second;

    //LEFT - Ci
    first = CiDi[0];
    second = CiDi[1];
    for(int i=0;i<26;i++){
      CiDi[i] = CiDi[i+2];
    }
    CiDi[26] = first;
    CiDi[27] = second;

    //RIGHT - Di
    first = CiDi[28];
    second = CiDi[29];
    for(int i=28;i<54;i++){
      CiDi[i] = CiDi[i+2];
    }
    CiDi[54] = first;
    CiDi[55] = second;

  }

}

void AES::PC_2(char * CiDi,char * subKeyStorage){
  for(int i=0;i<48;i++){
    subKeyStorage[i] = CiDi[table_pc_2[i]-1];
  }
}

char * AES::xorBINARY(char * first, char * second, int len){
  char * res = new char[len];
  for(int i=0;i<len;i++){
    res[i] = first[i]^second[i];
  }
  return res;
}

char * AES::E(char * R){
  char * res = new char[48];
  for(int i=0;i<48;i++){
    res[i] = R[table_e[i]-1];
  }
  return res;
}

char * AES::S(char * resXOR){
  char * res = new char[32];
  int j=0;
  int k=0;
  for(int i=0;i<48;i=i+6){
    int row = 2*resXOR[i] + resXOR[i+5];
    int col = 8*resXOR[i+1] + 4*resXOR[i+2] + 2*resXOR[i+3] + resXOR[i+4];
    int value = table_s[j][row][col];
    j++;
    for(int x = 8; x>0; x>>= 1){
      res[k] = ((value & x) == x) ? 1:0;
      k++;
    }
  }
  return res;

}

char * AES::P(char * resS){
  char * res = new char[32];
  for(int i =0;i<32;i++){
    res[i] = resS[table_p[i]-1];
  }
  return res;
}

char * AES::F(char * R, char * K){
  char * resE = E(R);
  char * resXOR = xorBINARY(resE,K,48);
  char * resS = S(resXOR);
  char * resP = P(resS);
  return resP;
}

void AES::iterate(char * binaryBlock , char * subKey){
  char L_OLD[32];
  char R_OLD[32];
  memcpy(L_OLD,binaryBlock,32);
  memcpy(R_OLD,&binaryBlock[32],32);
  char * resF = F(R_OLD,subKey);
  char * R_NEW = xorBINARY(L_OLD,resF,32);
  memcpy(binaryBlock,R_OLD,32);
  memcpy(&binaryBlock[32],R_NEW,32);
}

void AES::swapLeftAndRight(char * binaryBlock, int bits){
  int halfLen = bits/2;
  char temp[halfLen];
  memcpy(temp,binaryBlock,halfLen);
  memcpy(binaryBlock,&binaryBlock[halfLen],halfLen);
  memcpy(&binaryBlock[halfLen],temp,halfLen);
}

unsigned char * AES::PaddingNulls(unsigned char in[], unsigned int inLen, unsigned int alignLen)
{
  unsigned char *alignIn = new unsigned char[alignLen];
  memcpy(alignIn, in, inLen);
  memset(alignIn + inLen, 0x00, alignLen - inLen);
  return alignIn;
}

unsigned int AES::GetPaddingLength(unsigned int len)
{
  unsigned int lengthWithPadding =  (len / blockBytesLen);
  if (len % blockBytesLen) {
	  lengthWithPadding++;
  }
  
  lengthWithPadding *=  blockBytesLen;
  
  return lengthWithPadding;
}

void AES::EncryptBlock(unsigned char in[], unsigned char out[], unsigned  char key[])
{
  unsigned char *w = new unsigned char[4 * Nb * (Nr + 1)];
  KeyExpansion(key, w);
  unsigned char **state = new unsigned char *[4];
  state[0] = new unsigned  char[4 * Nb];
  int i, j, round;
  for (i = 0; i < 4; i++)
  {
    state[i] = state[0] + Nb * i;
  }


  for (i = 0; i < 4; i++)
  {
    for (j = 0; j < Nb; j++)
    {
      state[i][j] = in[i + 4 * j];
    }
  }

  AddRoundKey(state, w);

  for (round = 1; round <= Nr - 1; round++)
  {
    SubBytes(state);
    ShiftRows(state);
    MixColumns(state);
    AddRoundKey(state, w + round * 4 * Nb);
  }

  SubBytes(state);
  ShiftRows(state);
  AddRoundKey(state, w + Nr * 4 * Nb);

  for (i = 0; i < 4; i++)
  {
    for (j = 0; j < Nb; j++)
    {
      out[i + 4 * j] = state[i][j];
    }
  }

  delete[] state[0];
  delete[] state;
  delete[] w;
}

void AES::DecryptBlock(unsigned char in[], unsigned char out[], unsigned  char key[])
{
  unsigned char *w = new unsigned char[4 * Nb * (Nr + 1)];
  KeyExpansion(key, w);
  unsigned char **state = new unsigned char *[4];
  state[0] = new unsigned  char[4 * Nb];
  int i, j, round;
  for (i = 0; i < 4; i++)
  {
    state[i] = state[0] + Nb * i;
  }


  for (i = 0; i < 4; i++)
  {
    for (j = 0; j < Nb; j++) {
      state[i][j] = in[i + 4 * j];
    }
  }

  AddRoundKey(state, w + Nr * 4 * Nb);

  for (round = Nr - 1; round >= 1; round--)
  {
    InvSubBytes(state);
    InvShiftRows(state);
    AddRoundKey(state, w + round * 4 * Nb);
    InvMixColumns(state);
  }

  InvSubBytes(state);
  InvShiftRows(state);
  AddRoundKey(state, w);

  for (i = 0; i < 4; i++)
  {
    for (j = 0; j < Nb; j++) {
      out[i + 4 * j] = state[i][j];
    }
  }

  delete[] state[0];
  delete[] state;
  delete[] w;
}


void AES::SubBytes(unsigned char **state)
{
  int i, j;
  unsigned char t;
  for (i = 0; i < 4; i++)
  {
    for (j = 0; j < Nb; j++)
    {
      t = state[i][j];
      state[i][j] = sbox[t / 16][t % 16];
    }
  }

}

void AES::ShiftRow(unsigned char **state, int i, int n)    // shift row i on n positions
{
  unsigned char t;
  int k, j;
  for (k = 0; k < n; k++)
  {
    t = state[i][0];
    for (j = 0; j < Nb - 1; j++)
    {
      state[i][j] = state[i][j + 1];
    }
    state[i][Nb - 1] = t;
  }
}

void AES::ShiftRows(unsigned char **state)
{
  ShiftRow(state, 1, 1);
  ShiftRow(state, 2, 2);
  ShiftRow(state, 3, 3);
}

unsigned char AES::xtime(unsigned char b)    // multiply on x
{
  unsigned char mask = 0x80, m = 0x1b;
  unsigned char high_bit = b & mask;
  b = b << 1;
  if (high_bit) {    // mod m(x)
    b = b ^ m;
  }
  return b;
}

unsigned char AES::mul_bytes(unsigned char a, unsigned char b)
{
  unsigned char c = 0, mask = 1, bit, d;
  int i, j;
  for (i = 0; i < 8; i++)
  {
    bit = b & mask;
    if (bit)
    {
      d = a;
      for (j = 0; j < i; j++)
      {    // multiply on x^i
        d = xtime(d);
      }
      c = c ^ d;    // xor to result
    }
    b = b >> 1;
  }
  return c;
}

void AES::MixColumns(unsigned char **state)
{
  unsigned char s[4], s1[4];
  int i, j;

  for (j = 0; j < Nb; j++)
  {
    for (i = 0; i < 4; i++)
    {
      s[i] = state[i][j];
    }

    s1[0] = mul_bytes(0x02, s[0]) ^ mul_bytes(0x03, s[1]) ^ s[2] ^ s[3];
    s1[1] = s[0] ^ mul_bytes(0x02, s[1]) ^ mul_bytes(0x03, s[2]) ^ s[3];
    s1[2] = s[0] ^ s[1] ^ mul_bytes(0x02, s[2]) ^ mul_bytes(0x03, s[3]);
    s1[3] = mul_bytes(0x03, s[0]) ^ s[1] ^ s[2] ^ mul_bytes(0x02, s[3]);
    for (i = 0; i < 4; i++)
    {
      state[i][j] = s1[i];
    }

  }

}

void AES::AddRoundKey(unsigned char **state, unsigned char *key)
{
  int i, j;
  for (i = 0; i < 4; i++)
  {
    for (j = 0; j < Nb; j++)
    {
      state[i][j] = state[i][j] ^ key[i + 4 * j];
    }
  }
}

void AES::SubWord(unsigned char *a)
{
  int i;
  for (i = 0; i < 4; i++)
  {
    a[i] = sbox[a[i] / 16][a[i] % 16];
  }
}

void AES::RotWord(unsigned char *a)
{
  unsigned char c = a[0];
  a[0] = a[1];
  a[1] = a[2];
  a[2] = a[3];
  a[3] = c;
}

void AES::XorWords(unsigned char *a, unsigned char *b, unsigned char *c)
{
  int i;
  for (i = 0; i < 4; i++)
  {
    c[i] = a[i] ^ b[i];
  }
}

void AES::Rcon(unsigned char * a, int n)
{
  int i;
  unsigned char c = 1;
  for (i = 0; i < n - 1; i++)
  {
    c = xtime(c);
  }

  a[0] = c;
  a[1] = a[2] = a[3] = 0;
}

void AES::KeyExpansion(unsigned char key[], unsigned char w[])
{
  unsigned char *temp = new unsigned char[4];
  unsigned char *rcon = new unsigned char[4];

  int i = 0;
  while (i < 4 * Nk)
  {
    w[i] = key[i];
    i++;
  }

  i = 4 * Nk;
  while (i < 4 * Nb * (Nr + 1))
  {
    temp[0] = w[i - 4 + 0];
    temp[1] = w[i - 4 + 1];
    temp[2] = w[i - 4 + 2];
    temp[3] = w[i - 4 + 3];

    if (i / 4 % Nk == 0)
    {
        RotWord(temp);
        SubWord(temp);
        Rcon(rcon, i / (Nk * 4));
      XorWords(temp, rcon, temp);
    }
    else if (Nk > 6 && i / 4 % Nk == 4)
    {
      SubWord(temp);
    }

    w[i + 0] = w[i - 4 * Nk] ^ temp[0];
    w[i + 1] = w[i + 1 - 4 * Nk] ^ temp[1];
    w[i + 2] = w[i + 2 - 4 * Nk] ^ temp[2];
    w[i + 3] = w[i + 3 - 4 * Nk] ^ temp[3];
    i += 4;
  }

  delete []rcon;
  delete []temp;

}


void AES::InvSubBytes(unsigned char **state)
{
  int i, j;
  unsigned char t;
  for (i = 0; i < 4; i++)
  {
    for (j = 0; j < Nb; j++)
    {
      t = state[i][j];
      state[i][j] = inv_sbox[t / 16][t % 16];
    }
  }
}

void AES::InvMixColumns(unsigned char **state)
{
  unsigned char s[4], s1[4];
  int i, j;

  for (j = 0; j < Nb; j++)
  {
    for (i = 0; i < 4; i++)
    {
      s[i] = state[i][j];
    }
    s1[0] = mul_bytes(0x0e, s[0]) ^ mul_bytes(0x0b, s[1]) ^ mul_bytes(0x0d, s[2]) ^ mul_bytes(0x09, s[3]);
    s1[1] = mul_bytes(0x09, s[0]) ^ mul_bytes(0x0e, s[1]) ^ mul_bytes(0x0b, s[2]) ^ mul_bytes(0x0d, s[3]);
    s1[2] = mul_bytes(0x0d, s[0]) ^ mul_bytes(0x09, s[1]) ^ mul_bytes(0x0e, s[2]) ^ mul_bytes(0x0b, s[3]);
    s1[3] = mul_bytes(0x0b, s[0]) ^ mul_bytes(0x0d, s[1]) ^ mul_bytes(0x09, s[2]) ^ mul_bytes(0x0e, s[3]);

    for (i = 0; i < 4; i++)
    {
      state[i][j] = s1[i];
    }
  }
}

void AES::InvShiftRows(unsigned char **state)
{
  ShiftRow(state, 1, Nb - 1);
  ShiftRow(state, 2, Nb - 2);
  ShiftRow(state, 3, Nb - 3);
}

void AES::XorBlocks(unsigned char *a, unsigned char * b, unsigned char *c, unsigned int len)
{
  for (unsigned int i = 0; i < len; i++)
  {
    c[i] = a[i] ^ b[i];
  }
}

void AES::printHexArray (unsigned char *a, unsigned int n)
{
	for (int i = 0; i < n; i++) {
	  printf("%02x ", a[i]);
	}
}

std::string AES::hexify(unsigned int n)
{
    std::string res;
    do
    {
        res += "0123456789ABCDEF"[n % 16];
        n >>= 4;
    }while(n);
    
    return std::string(res.rbegin(), res.rend());
}







