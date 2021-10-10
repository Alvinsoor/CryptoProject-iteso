#include <stdio.h>
#include <sodium.h>

#define CHUNK_SIZE 4096

static int
createPass(unsigned char* password[128]) {		//Crear una contraseña cifrada
	unsigned char key[crypto_secretbox_KEYBYTES];       //Asignamos nuestras variables con los tamaños
	unsigned char nonce[crypto_secretbox_NONCEBYTES];   //definidos por la libreria de libsodium
	unsigned char ciphertext[crypto_secretbox_MACBYTES + 128];
	unsigned char decrypted[128];
	crypto_secretbox_keygen(key);				//Crea una llave
	randombytes_buf(nonce, sizeof nonce);		//Crea el nonce

	FILE* fp_key, * fp_pass, * fp_nonce;		//Guarda la llave en un archivo key
	fp_key = fopen("tmp/key", "wb");
	fwrite(key, 1, sizeof(key), fp_key);
	fclose(fp_key);

	fp_nonce = fopen("tmp/nonce", "wb");		//Guarda el nonce en un archivo nonce
	fwrite(nonce, 1, sizeof(nonce), fp_nonce);
	fclose(fp_nonce);

	crypto_secretbox_easy(ciphertext, password, 128, nonce, key);	//Encripta la contraseña y la guarda en variable ciphertext

	fp_pass = fopen("tmp/password", "wb");					//Guarda la contraseña encriptada en un archivo password
	fwrite(ciphertext, 1, sizeof(ciphertext), fp_pass);
	fclose(fp_pass);

	return 0;
}

static int
decryptPass() {				//tomamos la contraseña creada en los archivos para desencriptarla
	unsigned char key[crypto_secretbox_KEYBYTES];       //Asignamos nuestras variables con los tamaños
	unsigned char nonce[crypto_secretbox_NONCEBYTES];   //definidos por la libreria de libsodium
	unsigned char ciphertext[crypto_secretbox_MACBYTES + 128];
	unsigned char decrypted[128];

	FILE* fp_key, * fp_pass, * fp_nonce;

	fp_key = fopen("tmp/key", "rb");		//leemos archivo key y guardamos su contenido en variable key
	fread(key, sizeof(key), 1, fp_key);
	fclose(fp_key);

	fp_nonce = fopen("tmp/nonce", "rb");	//leemos archivo nonce y guardamos su contenido en variable nonce
	fread(nonce, sizeof(nonce), 1, fp_nonce);
	fclose(fp_nonce);

	fp_pass = fopen("tmp/password", "rb");	//leemos archivo password y guardamos su contenido en variable ciphertext
	fread(ciphertext, sizeof(ciphertext), 1, fp_pass);
	fclose(fp_pass);

	if (crypto_secretbox_open_easy(decrypted, ciphertext, crypto_secretbox_MACBYTES + 128, nonce, key) != 0) {	//Desencripta la contraseña
		printf("Message Forged!\n");																			//En caso de que no se pueda desencriptar la contraseña,
																												//asume que el mensaje ha sido forjado
	}

	printf("Your decrypted password is> %s \n\n", decrypted);	//Muestra la constraseña desencriptada
}

static int
encryptFile(const char* target_file, const char* source_file,		//Encripta un archivo elegido por el usuario
	const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES])
{	//Definimos variables
	unsigned char  buf_in[CHUNK_SIZE];
	unsigned char  buf_out[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
	unsigned char  header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
	crypto_secretstream_xchacha20poly1305_state st;
	FILE* fp_t, * fp_s;
	unsigned long long out_len;
	size_t         rlen;
	int            eof;
	unsigned char  tag;
	//abrimos el archivo y creamos el archivo encriptado
	fp_s = fopen(source_file, "rb");
	fp_t = fopen(target_file, "wb");
	crypto_secretstream_xchacha20poly1305_init_push(&st, header, key);
	fwrite(header, 1, sizeof header, fp_t);
	do {		//Leemos y agregamos la encripcion al archivo encrypted
		rlen = fread(buf_in, 1, sizeof buf_in, fp_s);
		eof = feof(fp_s);
		tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
		crypto_secretstream_xchacha20poly1305_push(&st, buf_out, &out_len, buf_in, rlen,
			NULL, 0, tag);
		fwrite(buf_out, 1, (size_t)out_len, fp_t);
	} while (!eof);	//loop hasta llegar al final de el archivo
	//cerramos archivos
	fclose(fp_t);
	fclose(fp_s);
	return 0;
}

static int
decryptFile(const char* target_file, const char* source_file,		//toma el archivo encriptado y lo des encripta
	const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES])
{//definimos variables
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
	//abrimos el archivo encriptado y creamos el archivo desencriptado
	fp_s = fopen(source_file, "rb");
	fp_t = fopen(target_file, "wb");
	fread(header, 1, sizeof header, fp_s);
	if (crypto_secretstream_xchacha20poly1305_init_pull(&st, header, key) != 0) {
		goto ret; /* incomplete header */
	}
	do {//desencriptamos el archivo
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
	} while (!eof); //terminamos llegando al final del archivo

	ret = 0;
ret:
	//cerramos el archivo
	fclose(fp_t);
	fclose(fp_s);
	return ret;
}

signString(unsigned char* str[128]) {	//toma un String y lo firma para confirmar su origen
	//definimos variables
	unsigned char pk[crypto_sign_PUBLICKEYBYTES];
	unsigned char sk[crypto_sign_SECRETKEYBYTES];
	crypto_sign_keypair(pk, sk);//firmamos el private y public key

	FILE* fp_pk, * fp_sk, * fp_signed, * fp_signlen;

	//guardamos public key en un archivo pk
	fp_pk = fopen("tmp/pk", "wb");
	fwrite(pk, 1, sizeof(pk), fp_pk);
	fclose(fp_pk);
	//guardamos private key en un archivo sk
	fp_sk = fopen("tmp/sk", "wb");
	fwrite(sk, 1, sizeof(sk), fp_sk);
	fclose(fp_sk);

	unsigned char signed_message[crypto_sign_BYTES + 128];
	unsigned long long signed_message_len;

	//tomamos el mensaje y lo guardamos en una variale firmada, junto con su longitud
	crypto_sign(signed_message, &signed_message_len, str, 128, sk);


	//guardamos el mensaje firmado en un archivo signedmessage
	fp_signed = fopen("tmp/signedmessage", "wb");
	fwrite(signed_message, 1, sizeof(signed_message), fp_signed);
	fclose(fp_signed);
	//guardamos la longitud del mensaje firmado en un archivo signlen
	fp_signlen = fopen("tmp/signlen", "wb");
	fwrite(&signed_message_len, 1, sizeof(signed_message_len), fp_signlen);
	fclose(fp_signlen);
}


verifyString() {		//tomamos el mensaje firmado y verificamos que no haya sido forjado
	//definimos variable
	unsigned char pk[crypto_sign_PUBLICKEYBYTES];
	unsigned char sk[crypto_sign_SECRETKEYBYTES];
	unsigned char signed_message[crypto_sign_BYTES + 128];
	unsigned long long signed_message_len;

	//abrimos archivos y guardamos su contenido en variables
	FILE* fp_pk, * fp_sk, * fp_signed, * fp_signlen;

	fp_pk = fopen("tmp/pk", "rb");
	fread(pk, sizeof(pk), 1, fp_pk);
	fclose(fp_pk);

	fp_sk = fopen("tmp/sk", "rb");
	fread(sk, sizeof(sk), 1, fp_sk);
	fclose(fp_sk);

	fp_signed = fopen("tmp/signedmessage", "rb");
	fread(signed_message, sizeof(signed_message), 1, fp_signed);
	fclose(fp_signed);

	fp_signlen = fopen("tmp/signlen", "rb");
	fread(&signed_message_len, sizeof(long long), 1, fp_signlen);
	fclose(fp_signlen);

	//definimos variables donde guardaremos el mensaje sin firmar y su longitud
	unsigned char unsigned_message[128]; 
	unsigned long long unsigned_message_len;

	//verificamos la veracidad del mensaje
	if (crypto_sign_open(unsigned_message, &unsigned_message_len, signed_message, signed_message_len, pk) != 0) {
		printf("Incorrect signature!\n");	//si el mensaje es incorrecto
	}
	else
		printf("Correct signature!\n");		//si el mensaje es correcto
}



int
main(void)
{

	if (sodium_init() != 0) {	//iniciamos libsodium
		return 1;
	}

	unsigned char* password[128];
	//pedimos al usuario ingresar su contraseña a encriptar
	printf("What will be your password?\n");
	scanf("%s", &password);

	//encriptamos la contraseña
	createPass(password);
	//desencriptamos la contraseña desde los archivos
	decryptPass();
	//pedimos al usuario un mensaje a firmar
	printf("What message will you sign?\n");
	scanf("%s", &password);
	//firmamos el mensaje
	signString(password);
	//verificamos la firma del mensaje
	verifyString();



	char* file[128];

	//pedimos al usuario una direccion de su archivo a encriptar
	printf("Please paste the full directory of the file to encrypt\n");
	scanf("%s", &file);
	//generamos una llave
	unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
	crypto_secretstream_xchacha20poly1305_keygen(key);
	//encriptamos el archivo
	if (encryptFile("tmp/encryptedFile", file, key) != 0) {
		return 1;
	}
	//desencriptamos el archivo
	if (decryptFile("tmp/decryptedFile", "tmp/encryptedFile", key) != 0) {
		return 1;
	}
	return 0;


}