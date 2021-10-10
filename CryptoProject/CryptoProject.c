#include <stdio.h>
#include <sodium.h>

#define CHUNK_SIZE 4096

static int
createPass(unsigned char* password[128]) {
    unsigned char key[crypto_secretbox_KEYBYTES];       //Asignamos nuestras variables con los tamaños
    unsigned char nonce[crypto_secretbox_NONCEBYTES];   //definidos por la libreria de libsodium
    unsigned char ciphertext[crypto_secretbox_MACBYTES + 128];
    unsigned char decrypted[128];
    crypto_secretbox_keygen(key);
    randombytes_buf(nonce, sizeof nonce);

    FILE* fp_key,* fp_pass, * fp_nonce;
    fp_key = fopen("tmp/key", "wb");
    fwrite(key, 1, sizeof(key), fp_key);
    fclose(fp_key);

    fp_nonce = fopen("tmp/nonce", "wb");
    fwrite(nonce, 1, sizeof(nonce), fp_nonce);
    fclose(fp_nonce);

    crypto_secretbox_easy(ciphertext, password, 128, nonce, key);

    fp_pass = fopen("tmp/password", "wb");
    fwrite(ciphertext, 1, sizeof(ciphertext), fp_pass);
    fclose(fp_pass);

    if (crypto_secretbox_open_easy(decrypted, ciphertext, crypto_secretbox_MACBYTES + 128, nonce, key) != 0) {
        printf("Message Forged!\n");
    }

    printf("Your decrypted password is> %s \n\n", decrypted);

    return 0;
}

static int
decryptPass() {
    unsigned char key[crypto_secretbox_KEYBYTES];       //Asignamos nuestras variables con los tamaños
    unsigned char nonce[crypto_secretbox_NONCEBYTES];   //definidos por la libreria de libsodium
    unsigned char ciphertext[crypto_secretbox_MACBYTES + 128];
    unsigned char decrypted[128];

    FILE* fp_key, * fp_pass, * fp_nonce;

    fp_key = fopen("tmp/key", "rb");
    fread(key, sizeof(key), 1, fp_key);
    fclose(fp_key);

    fp_nonce = fopen("tmp/nonce", "rb");
    fread(nonce, sizeof(nonce), 1, fp_nonce);
    fclose(fp_nonce);

    fp_pass = fopen("tmp/password", "rb");
    fread(ciphertext, sizeof(ciphertext), 1, fp_pass);
    fclose(fp_pass);
    
    if (crypto_secretbox_open_easy(decrypted, ciphertext, crypto_secretbox_MACBYTES + 128, nonce, key) != 0) {
        printf("Message Forged!\n");
    }

    printf("Your decrypted password is> %s \n\n", decrypted);
}

static int
encryptFile(const char* target_file, const char* source_file,
    const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES])
{
    unsigned char  buf_in[CHUNK_SIZE];
    unsigned char  buf_out[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char  header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state st;
    FILE* fp_t, * fp_s;
    unsigned long long out_len;
    size_t         rlen;
    int            eof;
    unsigned char  tag;

    fp_s = fopen(source_file, "rb");
    fp_t = fopen(target_file, "wb");
    crypto_secretstream_xchacha20poly1305_init_push(&st, header, key);
    fwrite(header, 1, sizeof header, fp_t);
    do {
        rlen = fread(buf_in, 1, sizeof buf_in, fp_s);
        eof = feof(fp_s);
        tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
        crypto_secretstream_xchacha20poly1305_push(&st, buf_out, &out_len, buf_in, rlen,
            NULL, 0, tag);
        fwrite(buf_out, 1, (size_t)out_len, fp_t);
    } while (!eof);
    fclose(fp_t);
    fclose(fp_s);
    return 0;
}

static int
decryptFile(const char* target_file, const char* source_file,
    const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES])
{
    unsigned char  buf_in[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char  buf_out[CHUNK_SIZE];
    unsigned char  header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state st;
    FILE* fp_t, * fp_s;
    unsigned long long out_len;
    size_t         rlen;
    int            eof;
    int            ret = -1;
    unsigned char  tag;

    fp_s = fopen(source_file, "rb");
    fp_t = fopen(target_file, "wb");
    fread(header, 1, sizeof header, fp_s);
    if (crypto_secretstream_xchacha20poly1305_init_pull(&st, header, key) != 0) {
        goto ret; /* incomplete header */
    }
    do {
        rlen = fread(buf_in, 1, sizeof buf_in, fp_s);
        eof = feof(fp_s);
        if (crypto_secretstream_xchacha20poly1305_pull(&st, buf_out, &out_len, &tag,
            buf_in, rlen, NULL, 0) != 0) {
            goto ret; /* corrupted chunk */
        }
        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL && !eof) {
            goto ret; /* premature end (end of file reached before the end of the stream) */
        }
        fwrite(buf_out, 1, (size_t)out_len, fp_t);
    } while (!eof);

    ret = 0;
ret:
    fclose(fp_t);
    fclose(fp_s);
    return ret;
}



int
main(void)
{
    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];

    if (sodium_init() != 0) {
        return 1;
    }

    unsigned char* password[128];

    printf("What will be your password?\n");
    scanf("%s", &password);


    createPass(password);

    decryptPass();
    


    char* file[128];
    printf("Please paste the full directory of the file to encrypt\n");
    scanf("%s", &file);

    crypto_secretstream_xchacha20poly1305_keygen(key);
    if (encryptFile("tmp/encryptedFile", file, key) != 0) {
        return 1;
    }
    if (decryptFile("tmp/decryptedFile", "tmp/encryptedFile", key) != 0) {
        return 1;
    }
    return 0;


}