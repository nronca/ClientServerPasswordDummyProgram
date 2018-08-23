package project1;

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


public class Target1 {
	protected static HashMap<String, String> passMap = new HashMap<String, String>();
	static Scanner c;
	static Target1 t;

	static Cipher AesCipher;
	static SecretKey secKey;
	static KeyGenerator keyGen;

	/*
	 * A use of oracle on I/O streams was referenced to set up the scanner
	 * for inputs, but not to solve the actual problem. 
	 */
	public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
		c = new Scanner(System.in);
		t = new Target1();
		keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(128);
		secKey = keyGen.generateKey();
		try {
			t.client();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	public void client() throws Exception{
		System.out.println("username: " );
		String username = c.nextLine();
		System.out.println("enter your password: ");

		String password = c.nextLine();
		username = aesEncrypt(username);
		password = aesEncrypt(password);
		t.server(username, password);
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
	public int server(String username, String password) throws Exception{
		username = aesDecrypt(username);
		password = aesDecrypt(password);
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
				t.client();//start over again

			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				passMap.notify();
			}
		}	
		return 0;
	}
	/*
	 * By following various oracle documentation on AES encryption
	 * I was able to obtain the general method for using a cipher
	 * and using it to decrypt and encrypt
	 */
	public static String aesEncrypt(String encrypt) throws Exception{
		String ret;

		AesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		byte[] byteText = encrypt.getBytes();

		AesCipher.init(Cipher.ENCRYPT_MODE, secKey);
		byte[] byteCipherText = AesCipher.doFinal(byteText);
		ret = new String(byteCipherText, "UTF-8");

		return ret;
	}
	public static String aesDecrypt(String decrypt) throws Exception {
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
}
