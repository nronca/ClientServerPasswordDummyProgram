package project1;

import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Formatter;
import java.util.HashMap;
import java.util.Scanner;
import java.util.concurrent.TimeUnit;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
//new imports
import javax.crypto.*;
import javax.crypto.spec.DHParameterSpec;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;

/*
 * Copyright (c) 1997, 2001, Oracle and/or its affiliates. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   - Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   - Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *   - Neither the name of Oracle nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* DISCLAIMER
 * 
 * I have used the above copyright to figure out how to add a key agreement
 * protocol between server and client. It has been modified to fit my needs
 * for this assignment going back and forth between server and client.
 *
 */

public class Target2 {
	protected static HashMap<String, String> passMap = new HashMap<String, String>();
	static Scanner c;
	static Target2 t;

	static Cipher AesCipher;
	//more new stuff
	static DHParameterSpec dhSkipParamSpec;
	static X509EncodedKeySpec x509KeySpec;
	static int serverLen, clientLen;
	private static SecretKey serverAesKey, clientAesKey;
	/*
	 * A use of oracle on I/O streams was referenced to set up the scanner
	 * for inputs, but not to solve the actual problem. 
	 */
	public static void main(String[] args) throws IOException, NoSuchAlgorithmException, Exception {
		c = new Scanner(System.in);
		t = new Target2();

		//here's an attempt to patch the illegalkeysize problem without downloading any files
		try {
			java.lang.reflect.Field field = Class.forName("javax.crypto.JceSecurity").getDeclaredField("isRestricted");
			field.setAccessible(true);
			field.set(null, java.lang.Boolean.FALSE);
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		//end attempt
		
		dhSkipParamSpec = new DHParameterSpec(skip1024Modulus, skip1024Base);
		try {
			t.client(0);//pass in zero for the first time we try to set up client server communications
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public String client(int retry) throws Exception{
		System.out.println("username: " );
		String username = c.nextLine();
		System.out.println("enter your password: ");

		String password = c.nextLine();
		if(retry != 0){//this means we failed the login attempt at least once
			username = aesEncrypt(username, clientAesKey);
			password = aesEncrypt(password, clientAesKey);
			t.server(username, password, null, 2);
			return null;
		}
		else{
			//creating own DH key pair, using DH parameters from above
			KeyPairGenerator clientKpairGen = KeyPairGenerator.getInstance("DH");
			clientKpairGen.initialize(dhSkipParamSpec);
			KeyPair clientKpair = clientKpairGen.generateKeyPair();

			//client creates and initializes DH keyagreement object
			KeyAgreement clientKeyAgree = KeyAgreement.getInstance("DH");
			clientKeyAgree.init(clientKpair.getPrivate());

			//now encode it to send to server
			byte[] clientPubKeyEnc = clientKpair.getPublic().getEncoded();
			byte[] serverPubKeyEnc;
			serverPubKeyEnc = t.server(null, null, clientPubKeyEnc, 2);

			//now we use server's pub key 
			KeyFactory clientKeyFac = KeyFactory.getInstance("DH");
			x509KeySpec = new X509EncodedKeySpec(serverPubKeyEnc);
			PublicKey serverPubKey = clientKeyFac.generatePublic(x509KeySpec);
			clientKeyAgree.doPhase(serverPubKey, true);
			t.server(null, null, clientPubKeyEnc, 0);

			//generating same shared secret
			byte[] clientSharedSecret = new byte[serverLen];

			//provide output buffer of required size
			clientLen = clientKeyAgree.generateSecret(clientSharedSecret, 0);
			clientKeyAgree.doPhase(serverPubKey, true);
			clientAesKey = clientKeyAgree.generateSecret("AES");
			t.server(null, null, clientPubKeyEnc, 1);

			//now we should be able to encrypt and send
			username = aesEncrypt(username, clientAesKey);
			password = aesEncrypt(password, clientAesKey);
			//System.out.println("username encrypted is " + username);
			//System.out.println("password encrypted is " + password);


			t.server(username, password, null, 2);

			return null;//for now
		}
	}	
	/*
	 * this helper function I am borrowing from stack over flow
	 * for an easy way to encrypt my eventual string 	
	 */
	private static String byteToHex(final byte[] hash){
		Formatter format = new Formatter();
		for (byte b : hash){
			format.format("%02x", b);
		}
		String ret = format.toString();
		format.close();
		return ret;
	}
	/*
	 * This function just hashes a password so it will be safely stored
	 */
	public static String hashPass(String password) throws NoSuchAlgorithmException, UnsupportedEncodingException{
		String encryptPass = "";
		MessageDigest encrypt = MessageDigest.getInstance("SHA-1");
		encrypt.update(password.getBytes("UTF-8"));
		encryptPass = byteToHex(encrypt.digest());

		return encryptPass;
	}
	public byte[] server(String username, String password, byte[] PubKeyEnc, int keyProtocol) throws Exception{
		KeyFactory serverKeyFac;
		PublicKey clientPubKey;
		DHParameterSpec dhParamSpec;
		KeyPairGenerator serverKpairGen;
		KeyPair serverKpair;
		KeyAgreement serverKeyAgree;
		byte[] serverPubKeyEnc, serverSharedSecret;


		if(PubKeyEnc == null && keyProtocol == 2){//this means all the key agreement protocols have been set up properly
			username = aesDecrypt(username, serverAesKey);
			password = aesDecrypt(password, serverAesKey);
			//System.out.println("username decrypted is " + username);
			//System.out.println("password decrypted is " + password);

			String encryptPass = "";
			encryptPass = hashPass(password);
			passMap.put(username, encryptPass);
			int fail = 0;
			while(fail < 5){
				if(fail>0){password = c.nextLine();}
				if(passMap.containsKey(username)){ 
					if(hashPass(password).equals(passMap.get(username))){
						System.out.println("Login successful! Exiting.");
						c.close();
						break;
					}
					else{
						fail++;
						System.out.println("incorrect password, you have " + (5-fail) + " more attempts.");
					}
				}
				else{
					System.out.println("incorrect username, exiting login");
					c.close();
					break;
				}
			}
			if(fail >= 5 ){
				System.out.println("5 failed attempts, you must now wait 3 minutes. \n");
				try {
					TimeUnit.MINUTES.sleep(3);
					//TimeUnit.SECONDS.sleep(5);
					t.client(1);//start over again

				} catch (InterruptedException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
					passMap.notify();
				}
			}	
			return null;
		}
		else{
			//we have clients pub key in encoded format
			//server will now instantiate a DH public key from this
			serverKeyFac = KeyFactory.getInstance("DH");
			x509KeySpec = new X509EncodedKeySpec(PubKeyEnc);
			clientPubKey = serverKeyFac.generatePublic(x509KeySpec);

			//server gets DH params assoc with client pub key
			//because we must use them to generate server's own key pair
			dhParamSpec = ((DHPublicKey)clientPubKey).getParams();

			//now we create our own DH key pair
			serverKpairGen = KeyPairGenerator.getInstance("DH");
			serverKpairGen.initialize(dhParamSpec);
			serverKpair = serverKpairGen.generateKeyPair();

			//now create and initialize DH keyagreement object
			serverKeyAgree = KeyAgreement.getInstance("DH");
			serverKeyAgree.init(serverKpair.getPrivate());

			//now server encodes pub key and returns it to client
			serverPubKeyEnc = serverKpair.getPublic().getEncoded();

			if(keyProtocol == 0){
				serverKeyAgree.doPhase(clientPubKey, true);

				//now at this point server and client have completed DH key agreement
				//both generate the same shared secret
				serverSharedSecret = serverKeyAgree.generateSecret();
				serverLen = serverSharedSecret.length;


				return null;
			}
			else if(keyProtocol == 1){
				serverKeyAgree.doPhase(clientPubKey, true);
				serverAesKey = serverKeyAgree.generateSecret("AES");

			}
			else{
				return serverPubKeyEnc;
			}
		}
		return null;
	}
	/*
	 * By following various oracle documentation on AES encryption
	 * I was able to obtain the general method for using a cipher
	 * and using it to decrypt and encrypt
	 */
	public static String aesEncrypt(String encrypt, SecretKey secKey) throws Exception{
		String ret;

		AesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		byte[] byteText = encrypt.getBytes();

		//int maxKeyLen = Cipher.getMaxAllowedKeyLength("AES");
		//System.out.println("max allowed key length for aes is " + maxKeyLen);
		//System.out.println("current secKey in string form is " + secKey.toString());

		AesCipher.init(Cipher.ENCRYPT_MODE, secKey);
		byte[] byteCipherText = AesCipher.doFinal(byteText);
		ret = new String(byteCipherText, "UTF-8");

		return ret;
	}
	public static String aesDecrypt(String decrypt, SecretKey secKey) throws Exception {
		String ret;
		byte[] cipherText1 = decrypt.getBytes("UTF-8");
		int x=cipherText1.length;
		while(x%16 !=0){
			x++;
		}
		byte[] cipherText = Arrays.copyOf(cipherText1, x);

		AesCipher = Cipher.getInstance("AES/ECB/NoPadding");
		AesCipher.init(Cipher.DECRYPT_MODE, secKey);
		byte[] bytePlainText = AesCipher.doFinal(cipherText);
		ret = new String(bytePlainText, "UTF-8");
		return ret;
	}
	/*
	 * These are more support functions from the DH key agreement I mentioned at the top of the file
	 * They are to keep key generation random each time this program is run
	 */
	// The 1024 bit Diffie-Hellman modulus values used by SKIP
	private static final byte skip1024ModulusBytes[] = {
		(byte)0xF4, (byte)0x88, (byte)0xFD, (byte)0x58,
		(byte)0x4E, (byte)0x49, (byte)0xDB, (byte)0xCD,
		(byte)0x20, (byte)0xB4, (byte)0x9D, (byte)0xE4,
		(byte)0x91, (byte)0x07, (byte)0x36, (byte)0x6B,
		(byte)0x33, (byte)0x6C, (byte)0x38, (byte)0x0D,
		(byte)0x45, (byte)0x1D, (byte)0x0F, (byte)0x7C,
		(byte)0x88, (byte)0xB3, (byte)0x1C, (byte)0x7C,
		(byte)0x5B, (byte)0x2D, (byte)0x8E, (byte)0xF6,
		(byte)0xF3, (byte)0xC9, (byte)0x23, (byte)0xC0,
		(byte)0x43, (byte)0xF0, (byte)0xA5, (byte)0x5B,
		(byte)0x18, (byte)0x8D, (byte)0x8E, (byte)0xBB,
		(byte)0x55, (byte)0x8C, (byte)0xB8, (byte)0x5D,
		(byte)0x38, (byte)0xD3, (byte)0x34, (byte)0xFD,
		(byte)0x7C, (byte)0x17, (byte)0x57, (byte)0x43,
		(byte)0xA3, (byte)0x1D, (byte)0x18, (byte)0x6C,
		(byte)0xDE, (byte)0x33, (byte)0x21, (byte)0x2C,
		(byte)0xB5, (byte)0x2A, (byte)0xFF, (byte)0x3C,
		(byte)0xE1, (byte)0xB1, (byte)0x29, (byte)0x40,
		(byte)0x18, (byte)0x11, (byte)0x8D, (byte)0x7C,
		(byte)0x84, (byte)0xA7, (byte)0x0A, (byte)0x72,
		(byte)0xD6, (byte)0x86, (byte)0xC4, (byte)0x03,
		(byte)0x19, (byte)0xC8, (byte)0x07, (byte)0x29,
		(byte)0x7A, (byte)0xCA, (byte)0x95, (byte)0x0C,
		(byte)0xD9, (byte)0x96, (byte)0x9F, (byte)0xAB,
		(byte)0xD0, (byte)0x0A, (byte)0x50, (byte)0x9B,
		(byte)0x02, (byte)0x46, (byte)0xD3, (byte)0x08,
		(byte)0x3D, (byte)0x66, (byte)0xA4, (byte)0x5D,
		(byte)0x41, (byte)0x9F, (byte)0x9C, (byte)0x7C,
		(byte)0xBD, (byte)0x89, (byte)0x4B, (byte)0x22,
		(byte)0x19, (byte)0x26, (byte)0xBA, (byte)0xAB,
		(byte)0xA2, (byte)0x5E, (byte)0xC3, (byte)0x55,
		(byte)0xE9, (byte)0x2F, (byte)0x78, (byte)0xC7
	};
	// The SKIP 1024 bit modulus
	private static final BigInteger skip1024Modulus
	= new BigInteger(1, skip1024ModulusBytes);

	// The base used with the SKIP 1024 bit modulus
	private static final BigInteger skip1024Base = BigInteger.valueOf(2);
}

