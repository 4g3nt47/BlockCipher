package com.umarabdul.crypto.blockcipher;

import java.io.*;
import java.util.Random;
import java.util.Scanner;


/**
* A simple block encryption library. It is NOT meant for protecting sensitive data, as the encryption it use is custom and weak.
*
* @author Umar Abdul
* @version 1.0
* @since 2020
*/

public class BlockCipher{

  private int blockSize;
  private byte[] table;
  private Random random;

  /**
  * The standard constructor, initializes the cryptographic lookup table using user supplied key and block size.
  * @param key Encryption key.
  * @param blockSize Number of bytes to work on at a time.
  */
  public BlockCipher(byte[] key, int blockSize){

    this.blockSize = blockSize;
    table = new byte[this.blockSize];
    long seed;
    // Initialize the cryptographic table using the given key.
    random = new Random();
    for (int i =  0; i < key.length; i++){
      random.setSeed((long)key[i]);
      seed = (long)(random.nextLong() * random.nextFloat());
      random.setSeed(seed + i);
    }
    for (int i = 0; i < table.length; i++)
      table[i] = (byte)random.nextInt((int)(Character.MAX_VALUE));
  }
  
  /**
  * Encrypt a given byte array, assuming {@code data.length == blockSize}.
  * @param data Array of bytes to encrypt.
  * @return Encrypted array of bytes.
  */
  public byte[] encrypt(final byte[] data){
    
    byte[] encoded = new byte[table.length];
    int j = 0;
    for (int i = 0; i < table.length ; i++)
      encoded[i] = (byte)(data[i] + table[i]);
    return encoded;
  }

  /**
  * Encrypt contents of an input stream and write to an output stream.
  * @param instream Input stream.
  * @param outstream Output stream.
  * @throws IOException on IO error.
  */
  public void encrypt(DataInputStream instream, DataOutputStream outstream) throws IOException{

    byte[] buffer = new byte[blockSize];
    byte[] encoded = new byte[blockSize];
    int count;
    while ((count = instream.read(buffer, 0, blockSize)) != -1){
      encoded = encrypt(buffer);
      if (count < blockSize){
        byte[] newBuffer = new byte[count];
        for (int i = 0; i < count; i++)
          newBuffer[i] = encoded[i];
        outstream.write(newBuffer, 0, count);
        continue;
      }
      outstream.write(encoded, 0, blockSize);
    }
    return;
  }

  /**
  * Decrypt a given byte array, assuming {@code data.length == blockSize}.
  * @param data Array of bytes to decrypt.
  * @return Decrypted array of bytes.
  */
  public byte[] decrypt(final byte[] data){
    
    byte[] decoded = new byte[table.length];
    int j = 0;
    for (int i = 0; i < table.length ; i++)
      decoded[i] = (byte)(data[i] - table[i]);
    return decoded;
  }

  /**
  * Decrypt contents of an input stream and write to an output stream.
  * @param instream Input stream.
  * @param outstream Output stream.
  * @throws IOException on IO error.
  */
  public void decrypt(DataInputStream instream, DataOutputStream outstream) throws IOException{

    byte[] buffer = new byte[blockSize];
    byte[] plain = new byte[blockSize];
    int count;
    while ((count = instream.read(buffer, 0, blockSize)) != -1){
      plain = decrypt(buffer);
      if (count < blockSize){
        byte[] newBuffer = new byte[count];
        for (int i = 0; i < count; i++)
          newBuffer[i] = plain[i];
        outstream.write(newBuffer, 0, count);
        continue;
      }
      outstream.write(plain, 0, blockSize);
    }
    return;
  }

  /**
  * Used for testing the library from command line.
  * @param args Command line arguments.
  * @throws IOException on IO error.
  */
  public static void main(String[] args) throws IOException{

    int blockSize = 4096;
    if (args.length != 3){
      System.out.println("[-] Args: <mode> <infile> <outfile>");
      return;
    }
    if (!(args[0].startsWith("enc") || args[0].startsWith("dec"))){
      System.out.println("[-] Invalid mode: " +args[0]);
      return;
    }
    Scanner sc = new Scanner(System.in);
    System.out.print("[*] Key > ");
    byte[] key = sc.nextLine().getBytes();
    File infile = new File(args[1]);
    File outfile = new File(args[2]);
    if (!(infile.exists())){
      System.out.println("[-] Invalid input file: " +args[2]);
      return;
    }
    boolean encMode = (args[0].startsWith("enc") ? true : false);
    if (encMode)
      System.out.println("[*] Encrypting file...");
    else
      System.out.println("[*] Decrypting file...");
    BlockCipher cipher = new BlockCipher(key, blockSize);
    DataInputStream reader = new DataInputStream(new FileInputStream(infile));
    DataOutputStream writer = new DataOutputStream(new FileOutputStream(outfile));
    long stime = System.nanoTime();
    if (encMode)
      cipher.encrypt(reader, writer);
    else
      cipher.decrypt(reader, writer);
    float duration = (float)(System.nanoTime() - stime) / 1000000000;
    System.out.println(String.format("[+] Done in: %.5f seconds", duration));
    reader.close();
    writer.close();
  }

}
