// 315CA_Mateescu_Pavel-Vlad_Tema3
#define _XOPEN_SOURCE 700
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

union record {
  char charptr[512];
  struct header {
    char name[100];
    char mode[8];
    char uid[8];
    char gid[8];
    char size[12];
    char mtime[12];
    char chksum[8];
    char typeflag;
    char linkname[100];
    char magic[8];
    char uname[32];
    char gname[32];
    char devmajor[8];
    char devminor[8];
  } header;
};
int calculatepermissions(char permissions[]) {
  int s = 0, i;
    for (i = 1; i < 10; i++) {
      if (i == 4) {
        s *= 10;
      }
      if (i == 7) s *= 10;
      if (permissions[i] == 'r') {
        s += 4;
      } else if (permissions[i] == 'w') {
        s += 2;
      } else if (permissions[i] == 'x') {
        s += 1;
      }
    }
    return s;
}
void create(char *archive_name, char *director_name) {
  union record h;
  memset(&h, 0, 512);
  char *permissions, *owner_name, *lct1, *lct2, *lct3, *name, *username,
      *encrypted_password, *uid, *gid, *no_links;
  char files[200], usermap[200], last_change_time[200], file[100], auxs[512],
      auxss[512];
  FILE *arh = fopen(archive_name, "wb");
  FILE *f = fopen("files.txt", "rt");
  FILE *u = fopen("usermap.txt", "rt");
  if (u == NULL || f == NULL || arh == NULL) {
    printf("> Failed!\n");
    return;
  }
  int done = 0, linecount = 0, i;
  while (fgets(files, 200, f)) {
    files[strlen(files) - 1] = 0;
    permissions = strtok(files, " ");
    sprintf(h.header.mode, "%07d", calculatepermissions(permissions));
    no_links = strtok(NULL, " ");
    strcpy(h.header.uname, strtok(NULL, " "));
    strcpy(h.header.gname, strtok(NULL, " "));
    sprintf(h.header.size, "%011o", atoi(strtok(NULL, " ")));
    lct1 = strtok(NULL, " ");
    lct2 = strtok(NULL, " ");
    lct3 = strtok(NULL, " ");
    name = strtok(NULL, " ");
    strcpy(h.header.name, name);
    if (done == 0) {
      fgets(usermap, 200, u);
      username = strtok(usermap, ":");
    }
    while (strcmp(username, h.header.uname) != 0 && done == 0) {
      fgets(usermap, 200, u);
      username = strtok(usermap, ":");
      linecount++;
    }
    if (done == 0) {
      encrypted_password = strtok(NULL, ":");
      sprintf(h.header.uid, "%07o", atoi(strtok(NULL, ":")));
      sprintf(h.header.gid, "%07o", atoi(strtok(NULL, ":")));
    }
    done = 1;
    lct2 = strtok(lct2, ".");
    strcpy(last_change_time, lct1);
    strcat(last_change_time, " ");
    strcat(last_change_time, lct2);
    struct tm time = {0};
    char *str = strptime(last_change_time, "%F %T", &time);
    time_t seconds = mktime(&time);
    sprintf(h.header.mtime, "%011lo", seconds);
    h.header.typeflag = '0';
    strcpy(h.header.linkname, name);
    strcpy(h.header.magic, "GNUtar ");
    sprintf(h.header.devmajor, "%07o", 0);
    sprintf(h.header.devminor, "%07o", 0);
    unsigned int chksum = 0;
    for (i = 0; i < 100; i++) chksum += h.header.name[i]
        + h.header.linkname[i];
    for (i = 0; i < 8; i++) chksum += h.header.mode[i] + h.header.uid[i]
        + h.header.gid[i] + h.header.magic[i] + h.header.devmajor[i]
        + h.header.devminor[i];
    for (i = 0; i < 12; i++) chksum += h.header.size[i] + h.header.mtime[i];
    chksum += h.header.typeflag;
    for (i = 0; i < 32; i++) chksum += h.header.uname[i] + h.header.gname[i];
    chksum += 8 * 32;
    sprintf(h.header.chksum, "%06o ", chksum);
    fwrite(h.charptr, 1, 512, arh);
    FILE *fl = fopen(name, "rb");
    int cc = fread(auxs, 1, 512, fl);
    while (cc == 512) {
      fwrite(auxs, 1, 512, arh);
      cc = fread(auxs, 1, 512, fl);
    }
    fwrite(auxs, 1, cc, arh);
    char pad = '\0';
    for (i = cc; i < 512; i++) fwrite(&pad, 1, 1, arh);
  }
  memset(&auxss, 0, 512);
  fwrite(auxss, sizeof(char), 512, arh);
  printf("> Done!\n");
}

void list(char *archive_name) {
  char auxs[512];
  memset(&auxs, 0, 512);
  FILE *fl = fopen(archive_name, "rb");
  if (fl == NULL) {
    printf("> File not found!\n");
    return;
  }
  char stop[10] = "\0\0\0\0\0\0\0\0\0";
  while (1) {
    fread(auxs, 10, sizeof(char), fl);
    if (strcmp(auxs, stop) == 0) break;
    printf("> %s\n", auxs);
    fread(auxs, 114, sizeof(char), fl);
    fread(auxs, 12, sizeof(char), fl);
    int octal = atoi(auxs), decimal = 0, i = 0, eight = 1;
    while (octal != 0) {
      decimal += (octal % 10) * eight;
      octal /= 10;
      i++;
      eight *= 8;
    }
    fread(auxs, 376, sizeof(char), fl);
    int nr;
    if (decimal % 512 == 0)
      nr = decimal / 512;
    else
      nr = decimal / 512 + 1;
    for (i = 1; i <= nr; i++) fread(auxs, 512, sizeof(char), fl);
  }
}
void extract(char *file_name, char *archive_name) {
  char auxs[512];
  char *size;
  char newfilename[100];
  strcpy(newfilename, "extracted_");
  strcat(newfilename, file_name);
  memset(&auxs, 0, 512);
  FILE *fl = fopen(archive_name, "rb");
  FILE *newfl = fopen(newfilename, "wb");
  int namesize = strlen(file_name);
  if (fl == NULL) {
    printf("> File not found!\n");
    return;
  }
  char stop[10] = "\0\0\0\0\0\0\0\0\0";
  int found = 0;
  while (1) {
    fread(auxs, 10, sizeof(char), fl);
    if (strcmp(auxs, stop) == 0) {
      printf("> File not found!\n");
      break;
    }
    if (memcmp(file_name, auxs, namesize) == 0) {
      found = 1;
    }
    fread(auxs, 114, sizeof(char), fl);
    fread(auxs, 12, sizeof(char), fl);
    int octal = atoi(auxs), decimal = 0, i = 0, eight = 1;
    while (octal != 0) {
      decimal += (octal % 10) * eight;
      octal /= 10;
      i++;
      eight *= 8;
    }
    fread(auxs, 376, sizeof(char), fl);
    int nr;
    if (decimal % 512 == 0)
      nr = decimal / 512;
    else
      nr = decimal / 512 + 1;
    if (found == 1) {
      char aux[1000000];
      memset(&aux, 0, decimal);
      fread(aux, 1, decimal, fl);
      fwrite(aux, 1, decimal, newfl);
      printf("> File extracted!\n");
      break;
    } else {
        for (i = 1; i <= nr; i++) {
          fread(auxs, 512, sizeof(char), fl);
        }
      }
  }
}

int main() {
  char *command;
  char *archive_name;
  char *file_name;
  char *director_name;
  int ok = 0;
  char commandline[200];
  fgets(commandline, 200, stdin);
  commandline[strlen(commandline) - 1] = 0;
  command = strtok(commandline, " ");
  while (strcmp(command, "exit") != 0) {
    if (strcmp(command, "create") == 0) {
      archive_name = strtok(NULL, " ");
      if (archive_name == NULL) ok = 1;
      director_name = strtok(NULL, " ");
      if (director_name == NULL) ok = 1;
      if (ok == 0) create(archive_name, director_name);
    }
    if (strcmp(command, "list") == 0) {
      archive_name = strtok(NULL, " ");
      if (archive_name == NULL) ok = 1;
      if (ok == 0) list(archive_name);
    }
    if (strcmp(command, "extract") == 0) {
      file_name = strtok(NULL, " ");
      if (file_name == NULL) ok = 1;
      archive_name = strtok(NULL, " ");
      if (archive_name == NULL) ok = 1;
      if (ok == 0) extract(file_name, archive_name);
    }
    if ((strcmp(command, "create") != 0 && strcmp(command, "list") != 0 &&
         strcmp(command, "extract") != 0 && strcmp(command, "exit") != 0) ||
        ok == 1)
      printf("Wrong command!\n");
    fgets(commandline, 200, stdin);
    commandline[strlen(commandline) - 1] = 0;
    command = strtok(commandline, " ");
    ok = 0;
  }
  return 0;
}
