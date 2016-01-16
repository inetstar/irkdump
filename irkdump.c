#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#define MAX_RECORDS 400

typedef struct {
  unsigned short used;
  unsigned char sys_extra;
  unsigned char sys;
  unsigned int provider;
  unsigned char id[4];
  unsigned char key[4][8];
} IrkRecord;

static int records;


/// @brief 
///
///

static void usage(void)
{
  puts("Usage:");
  puts("\tirkdump x irk_name_without_extention (extract .irk to .asc)");
  puts("or");
  puts("\tirkdump c irk_name_without_extention (create .irk from .asc)");
}


/// @brief extract Seca
///
///

static void extractSeca(FILE *ascFile, IrkRecord *rec)
{
  int part;
  for (part = 0; part < 4; part ++) {
    int pos;
    fprintf(ascFile, "S %04X %02X ", rec->provider, rec->id[part]);
    for (pos = 0; pos < 8; pos ++) {
      fprintf(ascFile, "%02X", rec->key[part][pos]);
    }
    fprintf(ascFile, "\n");
  }
}


/// @brief extract Viacess
///
///

static void extractViacess(FILE *ascFile, IrkRecord *rec)
{
  int part;
  for (part = 0; part < 4; part ++) {
    int pos;
    fprintf(ascFile, "V %06X %02X ", rec->provider, rec->id[part]);
    for (pos = 0; pos < 8; pos ++) {
      fprintf(ascFile, "%02X", rec->key[part][pos]);
    }
    fprintf(ascFile, "\n");
  }
}


/// @brief extract Irdeto/Beta
///
///

static void extractIrdetoBeta(FILE *ascFile, IrkRecord *rec)
{
  int part;
  for (part = 0; part < 4; part ++) {
    int pos;
    fprintf(ascFile, "I %02X %02X ", rec->provider, rec->id[part]);
    for (pos = 0; pos < 8; pos ++) {
      fprintf(ascFile, "%02X", rec->key[part][pos]);
    }
    fprintf(ascFile, "\n");
  }
}


/// @brief extract TPS AES
///
///

static void extractTpsAes(FILE *ascFile, IrkRecord *rec)
{
  int part;
  fprintf(ascFile, "T");
  for (part = 0; part < 2; part ++) {
    int pos;
    fprintf(ascFile, " ");
    for (pos = 0; pos < 8; pos ++) {
      fprintf(ascFile, "%02X", rec->key[part][pos]);
    }
  }
  fprintf(ascFile, "\n");
}


/// @brief extract CryptoWorks
///
///

static void extractCryptoWorks(FILE *ascFile, IrkRecord *rec)
{
  int part;
  for (part = 0; part < 4; part ++) {
    int pos;
    fprintf(ascFile, "W %04X %02X ", (rec->provider >> 8) & 0xFFFF, rec->provider & 0xFF);
    for (pos = 0; pos < 8; pos ++) {
      fprintf(ascFile, "%02X", rec->key[part][pos]);
    }
    fprintf(ascFile, "\n");
  }
}


/// @brief extract Nagra
///
///

static void extractNagra(FILE *ascFile, IrkRecord *rec)
{
  int part;
  for (part = 0; part < 4; part ++) {
    int pos;
    fprintf(ascFile, "N %04X %02X ", rec->provider, rec->id[part]);
    for (pos = 0; pos < 8; pos ++) {
      fprintf(ascFile, "%02X", rec->key[part][pos]);
    }
    fprintf(ascFile, "\n");
  }
}


/// @brief extract BISS
///
///

static void extractBiss(FILE *ascFile, IrkRecord *rec)
{
  int pos;
  fprintf(ascFile, "B %05u ", rec->provider);
  for (pos = 0; pos < 8; pos ++) {
     fprintf(ascFile, "%02X", rec->key[0][pos]);
  }
  fprintf(ascFile, " ");
  for (pos = 0; pos < 4; pos ++) {
     fprintf(ascFile, "%02X", rec->key[1][pos]);
  }
  fprintf(ascFile, "\n");
}


/// @brief extract ConstDW
///
///

static void extractConstDW(FILE *ascFile, IrkRecord *rec)
{
  int part;
  for (part = 0; part < 2; part ++) {
    int pos;
    fprintf(ascFile, "F %04X %04X ", rec->provider & 0xFFFF, (rec->provider >> 16) & 0xFFFF);
    for (pos = 0; pos < 8; pos ++) {
      fprintf(ascFile, "%02X", rec->key[part][pos]);
    }
    fprintf(ascFile, "\n");
  }
}


/// @brief extract .irk to .asc
///
///

static void extractIrk(const char *name)
{
  char *irkName, *ascName;
  FILE *irkFile, *ascFile;
  IrkRecord rec;
  int sys = -1;
  irkName = malloc(strlen(name) + 6);
  strcpy(irkName, name);
  strcat(irkName, ".irk");
  ascName = malloc(strlen(name) + 6);
  strcpy(ascName, name);
  strcat(ascName, ".asc");
  if ((irkFile = fopen(irkName, "rb")) == NULL) {
    fprintf(stderr, "Can`t open %s: %s\n", irkName, strerror(errno));
    exit(1);
  }
  if ((ascFile = fopen(ascName, "wt")) == NULL) {
    fprintf(stderr, "Can`t create %s: %s\n", ascName, strerror(errno));
    exit(1);
  }
  while (fread(&rec, sizeof(rec), 1, irkFile) == 1) {
    if (rec.used == 1) {
      if (sys != rec.sys) {
        sys = rec.sys;
        switch (sys) {
          case 0x01:
            fprintf(ascFile, "; Seca\n");
            break;
          case 0x05:
            fprintf(ascFile, "; Viacess\n");
            break;
          case 0x06:
            fprintf(ascFile, "; Irdeto/Beta\n");
            break;
          case 0x09:
            fprintf(ascFile, "; TPS AES\n");
            break;
          case 0x0D:
            fprintf(ascFile, "; CryptoWorks\n");
            break;
          case 0x18:
            fprintf(ascFile, "; Nagra\n");
            break;
          case 0x26:
            fprintf(ascFile, "; BISS\n");
            break;
          case 0xCF:
            fprintf(ascFile, "; ConstDW\n");
            break;
          default:
            fprintf(stderr, "Unknown record type: 0x%02X\n", sys);
            break;
        }
      }
      switch (sys) {
        case 0x01:
          extractSeca(ascFile, &rec);
          break;
        case 0x05:
          extractViacess(ascFile, &rec);
          break;
        case 0x06:
          extractIrdetoBeta(ascFile, &rec);
          break;
        case 0x09:
          extractTpsAes(ascFile, &rec);
          break;
        case 0x0D:
          extractCryptoWorks(ascFile, &rec);
          break;
        case 0x18:
          extractNagra(ascFile, &rec);
          break;
        case 0x26:
          extractBiss(ascFile, &rec);
          break;
        case 0xCF:
          extractConstDW(ascFile, &rec);
          break;
      }
    }
  }
  fclose(ascFile);
  fclose(irkFile);
  free(ascName);
  free(irkName);
}


/// @brief prepare .irk record
///
///

static void prepareIrk(IrkRecord *rec, int *irkCount)
{
  memset(rec, 0, sizeof(*rec));
  (*irkCount) = 0;
}


/// @brief write .irk record to .irk file
///
///

static void writeIrk(FILE *irkFile, IrkRecord *rec)
{

  if (records < MAX_RECORDS) {
    if (fwrite(rec, sizeof(*rec), 1, irkFile) < 1) {
      fprintf(stderr, ".irk file write error: %s\n", strerror(errno));
      exit(1);
    }
    records ++;
  }
  else {
    fprintf(stderr, ".irk file overflow!\n");
    exit(1);
  }
}


/// @brief flush .irk record to .irk file
///
///

static void flushIrk(FILE *irkFile, IrkRecord *rec, int *irkCount)
{
  if (*irkCount > 0) {
    writeIrk(irkFile, rec);
  }
  prepareIrk(rec, irkCount);
}


/// @brief put .irk record to .irk file
///
///

static void putIrk(FILE *irkFile, IrkRecord *rec, int *irkCount, unsigned char sys, unsigned char sys_extra,
                   unsigned int provider, unsigned char id, unsigned char key[8])
{
  if ((*irkCount) > 3 ||
      ((*irkCount) > 0 && (sys != rec->sys || sys_extra != rec->sys_extra || provider != rec->provider))) {
    flushIrk(irkFile, rec, irkCount);
  }
  rec->used = 1;
  rec->sys = sys;
  rec->sys_extra = sys_extra;
  rec->provider = provider;
  if (sys == 0x0D) {
    rec->id[0] = 0x00;
    rec->id[1] = 0x01;
    rec->id[2] = 0x10;
    rec->id[3] = 0x11;
  }
  else if (sys == 0xCF) {
    rec->id[0] = 0x00;
    rec->id[1] = 0x01;
  }
  else {
    rec->id[*irkCount] = id;
  }
  memcpy(rec->key[*irkCount], key, sizeof(rec->key[*irkCount]));
  (*irkCount) ++;
}


/// @brief get SID from line
///
///

static unsigned int getSID(char *line, int *pos, int numLine)
{
  unsigned int SID = 0;
  int c;
  int len = 0;
  while ((c = line[*pos]) == ' ' || c == '\t') {
    (*pos) ++;
  }
  while (1) {
    int ok = 0;
    c = line[*pos];
    if (c >= '0' && c <= '9') {
      c -= '0';
      ok = 1;
    }
    if (ok) {
      SID = SID * 10 + c;
      len ++;
      (*pos) ++;
    }
    else {
      break;
    }
  }
  if (len < 1 || len > 5) {
    fprintf(stderr, "Parse error at line %d\n", numLine);
    exit(1);
  }
  return SID;
}


/// @brief get provider ID from line
///
///

static unsigned int getProvider(char *line, int *pos, int numLine)
{
  unsigned int provider = 0;
  int c;
  int len = 0;
  while ((c = line[*pos]) == ' ' || c == '\t') {
    (*pos) ++;
  }
  while (1) {
    int ok = 0;
    c = line[*pos];
    if (c >= '0' && c <= '9') {
      c -= '0';
      ok = 1;
    }
    else if (c >= 'A' && c <= 'F') {
      c -= 'A' - 10;
      ok = 1;
    }
    else if (c >= 'a' && c <= 'f') {
      c -= 'a' - 10;
      ok = 1;
    }
    if (ok) {
      provider = (provider << 4) | c;
      len ++;
      (*pos) ++;
    }
    else {
      break;
    }
  }
  if (len < 1 || len > 8) {
    fprintf(stderr, "Parse error at line %d\n", numLine);
    exit(1);
  }
  return provider;
}


/// @brief get ID from line
///
///

static unsigned char getId(char *line, int *pos, int numLine)
{
  unsigned char id = 0;
  int c;
  int len = 0;
  while ((c = line[*pos]) == ' ' || c == '\t') {
    (*pos) ++;
  }
  while (1) {
    int ok = 0;
    c = line[*pos];
    if (c >= '0' && c <= '9') {
      c -= '0';
      ok = 1;
    }
    else if (c >= 'A' && c <= 'F') {
      c -= 'A' - 10;
      ok = 1;
    }
    else if (c >= 'a' && c <= 'f') {
      c -= 'a' - 10;
      ok = 1;
    }
    if (ok) {
      id = (id << 4) | c;
      len ++;
      (*pos) ++;
    }
    else {
      break;
    }
  }
  if (len < 1 || len > 2) {
    fprintf(stderr, "Parse error at line %d\n", numLine);
    exit(1);
  }
  return id;
}


/// @brief get key from line
///
///

static void getKey(unsigned char key[8], char *line, int *pos, int numLine)
{
  int c;
  int len = 0;
  while ((c = line[*pos]) == ' ' || c == '\t') {
    (*pos) ++;
  }
  while (1) {
    int ok = 0;
    c = line[*pos];
    if (c >= '0' && c <= '9') {
      c -= '0';
      ok = 1;
    }
    else if (c >= 'A' && c <= 'F') {
      c -= 'A' - 10;
      ok = 1;
    }
    else if (c >= 'a' && c <= 'f') {
      c -= 'a' - 10;
      ok = 1;
    }
    if (ok) {
      if (len < 16) {
        if ((len & 1) == 0) {
          key[len / 2] = c << 4;
        }
        else {
          key[len / 2] |= c;
        }
      }
      len ++;
      (*pos) ++;
    }
    else {
      break;
    }
  }
  if (len != 16) {
    fprintf(stderr, "Parse error at line %d\n", numLine);
    exit(1);
  }
}


/// @brief get PMT CRC from line
///
///

static void getPMTCRC(unsigned char PMTCRC[8], char *line, int *pos, int numLine)
{
  int i, c;
  int len = 0;
  while ((c = line[*pos]) == ' ' || c == '\t') {
    (*pos) ++;
  }
  for (i = 0; i < 8; i ++) {
    PMTCRC[i] = 0;
  }
  while (1) {
    int ok = 0;
    c = line[*pos];
    if (c >= '0' && c <= '9') {
      c -= '0';
      ok = 1;
    }
    else if (c >= 'A' && c <= 'F') {
      c -= 'A' - 10;
      ok = 1;
    }
    else if (c >= 'a' && c <= 'f') {
      c -= 'a' - 10;
      ok = 1;
    }
    if (ok) {
      if (len < 16) {
        if ((len & 1) == 0) {
          PMTCRC[len / 2] = c << 4;
        }
        else {
          PMTCRC[len / 2] |= c;
        }
      }
      len ++;
      (*pos) ++;
    }
    else {
      break;
    }
  }
  if (len != 0 && len != 8) {
    fprintf(stderr, "Parse error at line %d\n", numLine);
    exit(1);
  }
}


/// @brief create Seca
///
///

static void createSeca(FILE *irkFile, char *line, IrkRecord *rec, int *irkCount, int numLine)
{
  int pos;
  unsigned char sys = 0x01;
  unsigned int provider;
  unsigned char id;
  unsigned char key[8];
  pos = 1;
  provider = getProvider(line, &pos, numLine);
  id = getId(line, &pos, numLine);
  getKey(key, line, &pos, numLine);
  putIrk(irkFile, rec, irkCount, sys, 0, provider, id, key);
}


/// @brief create Viacess
///
///

static void createViacess(FILE *irkFile, char *line, IrkRecord *rec, int *irkCount, int numLine)
{
  int pos;
  unsigned char sys = 0x05;
  unsigned int provider;
  unsigned char id;
  unsigned char key[8];
  pos = 1;
  provider = getProvider(line, &pos, numLine);
  id = getId(line, &pos, numLine);
  getKey(key, line, &pos, numLine);
  putIrk(irkFile, rec, irkCount, sys, 0, provider, id, key);
}


/// @brief create Irdeto/Beta
///
///

static void createIrdetoBeta(FILE *irkFile, char *line, IrkRecord *rec, int *irkCount, int numLine)
{
  int pos;
  unsigned char sys = 0x06;
  unsigned int provider;
  unsigned char id;
  unsigned char key[8];
  pos = 1;
  provider = getProvider(line, &pos, numLine);
  id = getId(line, &pos, numLine);
  getKey(key, line, &pos, numLine);
  putIrk(irkFile, rec, irkCount, sys, 0, provider, id, key);
}


/// @brief create TPS AES
///
///

static void createTpsAes(FILE *irkFile, char *line, IrkRecord *rec, int *irkCount, int numLine)
{
  int pos;
  unsigned char sys = 0x09;
  unsigned int provider = 1;
  unsigned char key0[8];
  unsigned char key1[8];
  pos = 1;
  getKey(key0, line, &pos, numLine);
  getKey(key1, line, &pos, numLine);
  flushIrk(irkFile, rec, irkCount);
  putIrk(irkFile, rec, irkCount, sys, 0, provider, 0, key0);
  putIrk(irkFile, rec, irkCount, sys, 0, provider, 1, key1);
  flushIrk(irkFile, rec, irkCount);
}


/// @brief create CryptoWorks
///
///

static void createCryptoWorks(FILE *irkFile, char *line, IrkRecord *rec, int *irkCount, int numLine)
{
  int pos;
  unsigned char sys = 0x0D;
  unsigned int provider;
  unsigned char id;
  unsigned char key[8];
  pos = 1;
  provider = getProvider(line, &pos, numLine);
  id = getId(line, &pos, numLine);
  getKey(key, line, &pos, numLine);
  putIrk(irkFile, rec, irkCount, sys, 0, ((provider & 0xFFFF) << 8) | (id & 0xFF), 0, key);
}


/// @brief create Nagra
///
///

static void createNagra(FILE *irkFile, char *line, IrkRecord *rec, int *irkCount, int numLine)
{
  int pos;
  unsigned char sys = 0x18;
  unsigned int provider;
  unsigned char id;
  unsigned char key[8];
  pos = 1;
  provider = getProvider(line, &pos, numLine);
  id = getId(line, &pos, numLine);
  getKey(key, line, &pos, numLine);
  putIrk(irkFile, rec, irkCount, sys, 0, provider, id, key);
}


/// @brief create BISS
///
///

static void createBiss(FILE *irkFile, char *line, IrkRecord *rec, int *irkCount, int numLine)
{
  int pos;
  unsigned char sys = 0x26;
  unsigned int provider;
  unsigned char id = 0;
  unsigned char key[8];
  unsigned char PMTCRC[8];
  pos = 1;
  provider = getSID(line, &pos, numLine);
  getKey(key, line, &pos, numLine);
  getPMTCRC(PMTCRC, line, &pos, numLine);
  flushIrk(irkFile, rec, irkCount);
  putIrk(irkFile, rec, irkCount, sys, 0, provider, id, key);
  putIrk(irkFile, rec, irkCount, sys, 0, provider, id, PMTCRC);
  flushIrk(irkFile, rec, irkCount);
}


/// @brief create ConstDW
///
///

static void createConstDW(FILE *irkFile, char *line, IrkRecord *rec, int *irkCount, int numLine)
{
  int pos;
  unsigned char sys = 0xCF;
  unsigned char sys_extra = 0xFF;
  unsigned int provider;
  unsigned char id = 0;
  unsigned char key[8];
  unsigned int CAID;
  unsigned int ECMPID;
  pos = 1;
  CAID = getProvider(line, &pos, numLine);
  ECMPID = getProvider(line, &pos, numLine);
  provider = (CAID & 0xFFFF) | ((ECMPID & 0xFFFF) << 16);
  getKey(key, line, &pos, numLine);
  if ((*irkCount) >= 2) {
    flushIrk(irkFile, rec, irkCount);
  }
  putIrk(irkFile, rec, irkCount, sys, sys_extra, provider, id, key);
}


/// @brief create .irk from .asc
///
///

static void createIrk(const char *name)
{
  char *irkName, *ascName;
  FILE *irkFile, *ascFile;
  IrkRecord rec;
  int irkCount;
  int numLine;
  char line[1024];
  irkName = malloc(strlen(name) + 6);
  strcpy(irkName, name);
  strcat(irkName, ".irk");
  ascName = malloc(strlen(name) + 6);
  strcpy(ascName, name);
  strcat(ascName, ".asc");
  if ((ascFile = fopen(ascName, "rt")) == NULL) {
    fprintf(stderr, "Can`t open %s: %s\n", ascName, strerror(errno));
    exit(1);
  }
  if ((irkFile = fopen(irkName, "wb")) == NULL) {
    fprintf(stderr, "Can`t create %s: %s\n", irkName, strerror(errno));
    exit(1);
  }
  prepareIrk(&rec, &irkCount);
  numLine = 0;
  records = 0;
  while (fgets(line, sizeof(line), ascFile) != NULL) {
    numLine ++;
    switch (line[0]) {
      case 'S':
        createSeca(irkFile, line, &rec, &irkCount, numLine);
        break;
      case 'V':
        createViacess(irkFile, line, &rec, &irkCount, numLine);
        break;
      case 'I':
        createIrdetoBeta(irkFile, line, &rec, &irkCount, numLine);
        break;
      case 'T':
        createTpsAes(irkFile, line, &rec, &irkCount, numLine);
        break;
      case 'W':
        createCryptoWorks(irkFile, line, &rec, &irkCount, numLine);
        break;
      case 'N':
        createNagra(irkFile, line, &rec, &irkCount, numLine);
        break;
      case 'B':
        createBiss(irkFile, line, &rec, &irkCount, numLine);
        break;
      case 'F':
        createConstDW(irkFile, line, &rec, &irkCount, numLine);
        break;
    }
  }
  flushIrk(irkFile, &rec, &irkCount);
  printf("%d of %d records (%.2f%%) created\n", records, MAX_RECORDS, ((double) records) / ((double) MAX_RECORDS) * 100.0);
  while (records < MAX_RECORDS) {
    writeIrk(irkFile, &rec);
  }
  fclose(irkFile);
  fclose(ascFile);
  free(irkName);
  free(ascName);
}


/// @brief main function (start program)
///
///

int main(int argc, char *argv[])
{
  if (argc < 3) {
    usage();
    return 1;
  }
  if (strcmp(argv[1], "x") == 0) {
    extractIrk(argv[2]);
  }
  else if (strcmp(argv[1], "c") == 0) {
    createIrk(argv[2]);
  }
  else {
    usage();
    return 1;
  }
  return 0;
}
