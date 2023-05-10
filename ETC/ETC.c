#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <zlib.h>
#include <unistd.h>
#include <openssl/evp.h>

#define chunkSize 16384
char extension[5];

void keyGen(){
    unsigned char* key = malloc(sizeof(unsigned char)*257);
    srand(time(NULL));
    for (int i=0; i<256;i++){
        int r =rand()%16;
        if (r<10){
            key[i]='0'+r;
        }
        else{
            key[i]='a'+(r-10);
        }
    }
    key[256]='\0';
    printf("key is %s\n", key);
    FILE *fp = fopen("key", "wb");
    fwrite(key, sizeof(unsigned char), 256, fp);
    fclose(fp);
}

int fileCompression(const char *source, const char *dest)
{
    clock_t begin = clock();
    FILE *srcFile = fopen(source, "rb");
    FILE *dstFile = fopen(dest, "wb");


    int ret, flush;
    unsigned int have;
    z_stream strm;
    unsigned char in[chunkSize];
    unsigned char out[chunkSize];

    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;

    ret = deflateInit(&strm, Z_DEFAULT_COMPRESSION);

    do {
        strm.avail_in = fread(in, 1, chunkSize, srcFile);
        flush = feof(srcFile) ? Z_FINISH : Z_NO_FLUSH;
        strm.next_in = in;

        do {
            strm.avail_out = chunkSize;
            strm.next_out = out;
            ret = deflate(&strm, flush);
            have = chunkSize - strm.avail_out;
            if (fwrite(out, 1, have, dstFile) != have || ferror(dstFile)) {
                (void)deflateEnd(&strm);
                fclose(srcFile);
                fclose(dstFile);
                return -1;
            }
        } while (strm.avail_out == 0);

    } while (flush != Z_FINISH);

    (void)deflateEnd(&strm);
    fclose(srcFile);
    fclose(dstFile);
    clock_t end = clock();
    double runningTime = (double)(end-begin)/CLOCKS_PER_SEC;
    printf("\nCompression ran in %f\n", runningTime);
    return 0;
}

int decompress(const char* s2compressedOutput, const char* s3DecompressedOutput) {
    clock_t begin = clock();
    FILE* inFile = fopen(s2compressedOutput, "rb");
    FILE* outFile = fopen(s3DecompressedOutput, "wb");

    int ret;
    unsigned int have;
    z_stream strm;
    unsigned char in[chunkSize];
    unsigned char out[chunkSize];

    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;

    ret = inflateInit(&strm);

    do {
        strm.avail_in = fread(in, 1, chunkSize, inFile);
        if (ferror(inFile)) {
            (void)inflateEnd(&strm);
            fclose(inFile);
            fclose(outFile);
            return -1;
        }
        if (strm.avail_in == 0) {
            break;
        }
        strm.next_in = in;

        do {
            strm.avail_out = chunkSize;
            strm.next_out = out;
            ret = inflate(&strm, Z_NO_FLUSH);

            have = chunkSize - strm.avail_out;
            if (fwrite(out, 1, have, outFile) != have || ferror(outFile)) {
                (void)inflateEnd(&strm);
                fclose(inFile);
                fclose(outFile);
                return -1;
            }
        } while (strm.avail_out == 0);

    } while (ret != Z_STREAM_END);

    (void)inflateEnd(&strm);
    fclose(inFile);
    fclose(outFile);
    clock_t end = clock();
    double runningTime = (double)(end-begin)/CLOCKS_PER_SEC;
    printf("\nDecompression ran in %f\n", runningTime);
    return 0;
}



void decryption(char* inputFileStr){
    clock_t begin = clock();
    char currentFolder[1024];
    getcwd(currentFolder, sizeof(currentFolder));
    unsigned char key[257];

    if (strlen(inputFileStr)==0){
        printf("\nFull name of the file to decrypt:\n");
        scanf("%s", &inputFileStr);
    }

    if (access("key",F_OK)==0){
        printf("Reading key from existing binary file in %s\n", currentFolder);
        FILE *fp =fopen("key", "rb");
        fread(key, sizeof(unsigned char), 256, fp);
        key[256]='\0';
        fclose(fp);
        printf("\nExisting key is %s\n", key);
    }
    else{
        printf("No pre-existing key. Please create a key before decrypting the file.\n");
        return;
    }
    //pointer for input file to decrypt
    FILE *fp = fopen("s3DecompressedOutput","rb");
    if (fp==NULL){
        printf("There is no %s file in the current working directory\n",inputFileStr);
        return;
    }
    //pointer for output file after decryption
    char finalFileName[256]="s4decryptedOutput";
    strcat(finalFileName,extension);
    FILE *decryptedFile = fopen(finalFileName, "wb");
    if (decryptedFile == NULL) {
        printf("Failed to create decrypted file.\n");
        return;
    }

    fseek(fp, 0, SEEK_END);
    int inputFileSize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, NULL);

    // Buffer for reading input data (buffer size matching file size)
    unsigned char *inputBuffer = malloc(inputFileSize);

    // Buffer for decrypted data
    unsigned char *decryptedBuffer = malloc(inputFileSize + EVP_MAX_BLOCK_LENGTH);

    int bytesRead;
    int bytesWritten;
    int totalBytesWritten = 0;
    // Data decryption
    while ((bytesRead = fread(inputBuffer, 1, inputFileSize, fp)) > 0) {
        EVP_DecryptUpdate(ctx, decryptedBuffer, &bytesWritten, inputBuffer, bytesRead);
        fwrite(decryptedBuffer, 1, bytesWritten, decryptedFile);
        totalBytesWritten += bytesWritten;
    }
    
    EVP_DecryptFinal_ex(ctx, decryptedBuffer, &bytesWritten);
    fwrite(decryptedBuffer, 1, bytesWritten, decryptedFile);
    totalBytesWritten += bytesWritten;

    fclose(fp);
    fclose(decryptedFile);
    EVP_CIPHER_CTX_free(ctx);
    free(inputBuffer);
    free(decryptedBuffer);

    printf("Decrypted %d bytes.\n", totalBytesWritten);
    clock_t end = clock();
    double runningTime = (double)(end-begin)/CLOCKS_PER_SEC;
    printf("\nDecryption ran in %f\n", runningTime);
}


void encryption(char* inputFileStr){
    clock_t begin = clock();
    //printf("\ngetting in: %s\n", inputFileStr);
    char currentFolder[1024];
    getcwd(currentFolder, sizeof(currentFolder));
    unsigned char key[257];

    if (strlen(inputFileStr)==0){
        //printf("\n\ntesting\\n");
        //printf("\nFull name of the file to encrypt:\n");
        //scanf("%s", &inputFileStr);
        //printf("\nafter scanf: %s\n", inputFileStr);
        //scanf("%c");
    }

    if (access("key",F_OK)==0){
        printf("Reading key from existing binary file in %s\n", currentFolder);
        FILE *fp =fopen("key", "rb");
        fread(key, sizeof(unsigned char), 256, fp);
        key[256]='\0';
        fclose(fp);
        printf("\nExisting key is %s\n\n", key);
    }
    else{
        printf("No pre-existing key. Creating a key in %s\n", currentFolder);
        keyGen();
        //printf("value is %s", inputFileStr);
        encryption("");
        return;
    }
    //TEEEEEEEEEEEEESSSSSSSSSSSSSSSSSTTTTTTTTTTTTTTTTTTTT
    char tempInputFileString [128] ="input.txt";
    //printf("\nGOTBACKHERE : %s\n", inputFileStr);
    //strcpy(tempInputFileString, inputFileStr);
    strncpy(extension, tempInputFileString+strlen(tempInputFileString)-4,4);
    extension[4]='\0';

    //printf("testing : %s\n",extension);
    //pointer for encryption input
    
    //printf("\nGOTBACKHERE : %s\n", tempInputFileString);
    FILE *fp = fopen(tempInputFileString,"rb");
    if (fp==NULL){
        printf("%s does not exist in this directory\n",inputFileStr);
        return;
    }
    //char ouputFile[1024];
    fseek(fp, 0, SEEK_END);
    int inputFileSize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, NULL);
    
    //pointer for encyrption output
    FILE *encryptedFile = fopen("s1encryptedOutput", "wb");

    
    
    
    // Buffer matching input reading input data
    unsigned char *inputBuffer = malloc(inputFileSize);
    // Buffer matching  encrypted data
    unsigned char *encryptedBuffer = malloc(inputFileSize + EVP_MAX_BLOCK_LENGTH);

    int bytesRead;
    int bytesWritten;
    int totalBytesWritten = 0;

    // Data encryption
    while ((bytesRead = fread(inputBuffer, 1, inputFileSize, fp)) > 0) {
        EVP_EncryptUpdate(ctx, encryptedBuffer, &bytesWritten, inputBuffer, bytesRead);
        fwrite(encryptedBuffer, 1, bytesWritten, encryptedFile);
        totalBytesWritten += bytesWritten;
    }
    EVP_EncryptFinal_ex(ctx, encryptedBuffer, &bytesWritten);
    fwrite(encryptedBuffer, 1, bytesWritten, encryptedFile);
    totalBytesWritten += bytesWritten;
    
    fclose(fp);
    fclose(encryptedFile);
    EVP_CIPHER_CTX_free(ctx);
    free(inputBuffer);
    free(encryptedBuffer);
    //printf("Encrypted %d bytes.\n", totalBytesWritten);
    clock_t end = clock();
    double runningTime = (double)(end-begin)/CLOCKS_PER_SEC;
    printf("\nEncryption ran in %f\n", runningTime);
}

int main (int argc, char **argv){
    
    while (1) {
        printf("1.Encrypt\n2.Compress\n3.Decompress\n4.Decrypt\n5.Exit\n");
        int choice;
        scanf("%d", &choice);
        switch(choice){
            case 1:
                printf("Running encryption\n");
                encryption("");
                break;
            case 2:
                printf("Running Compression\n");
                fileCompression("s1encryptedOutput", "s2compressedOutput");
                break;
            case 3:
                printf("Running Decompression\n");
                decompress("s2compressedOutput", "s3DecompressedOutput");
                break;
            case 4:
                printf("Running decryption\n");
                decryption("s3DecompressedOutput");
                break;
            case 5:
                return 0;
                break;
        }
    }
    return 0;
}