/***********************************************************************
* FILENAME :        PseudoRandomOracleHelper.java             
*
* DESCRIPTION :
*       A Controller to Implement an encryption  oracle for the IND-CPA ciphertext distinguishing game
*
* PUBLIC FUNCTIONS :
*       
*
It's standard to model modern block ciphers as pseudo random functions. A secure multiple message mode of operation for a block cipher is said to be semantically secure if knowledge of a cipher text does not reveal any information about the key or the plaintext to a **polynomial time** adversary (cf. contrast with "perfect secrecy"). An equivalent definition of sematic security is ciphertext indistinguishbility under chosen plaintext attack (IND-CPA security). This definition is based on a distinguishing game where a polynomial time adversary chooses two distinct messages, m_1 and m_2, and submits them to an encrypting oracle that implements the PRF. The oracle then randomly picks one of the two messages, encrypts them with the PRF, and returns this ciphertext to the adversary. The scheme is semantically secure if the likelihood that the adversary can correctly guess the corresponding plaintext to the ciphertext is no greater than 1/2 plus some "negligible" advantage

Implementation details: 
1) The chosen block cipher is AES-128. The mode of operation is CTR
2) Input plaintexts are each 16 bytes long which is equal to the AES block size
4) The two plaintexts are passed in to the rest endpoint through the following URL and parameter as a 64 character concatenated hex string:
http://pseudorandomoracle.cfapps.io/oracle?plaintexts=e0c10203f40501070d99aa0c00d0890fa0c13203f40501070d99aa0c00d089ff
    
5) The first 32 characters in the above parameter value correspond to the first 16 byte plaintext message and the second 32 characters correspond to the second 16 byte plaintext message sent by the adversary

* AUTHOR :    Rohit Khera        START DATE :    Dec. 6 2015
*
* CHANGES :
*  
* REF NO  VERSION DATE    WHO     DETAIL
* 
*
*/




package hello;

//import java.security.MessageDigest;
//import java.util.Arrays;
//import javax.crypto.KeyGenerator;
//import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
 
import javax.crypto.Cipher;
 
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchProviderException;
import javax.crypto.BadPaddingException;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidAlgorithmParameterException;

//import java.util.Random;
//import java.io.File;
//import java.io.IOException;
//import java.io.PrintWriter;



public class PseudoRandomOracleHelper {




    private byte[] keyBytes = new byte[] { 0x70, (byte)0xc1, 0x02, 0x03, (byte)0xf4, 0x05, 0x01, 0x07, 0x0d, (byte)0x99,
					  (byte)0xaa, 0x0c, 0x00, (byte)0xd0, (byte)0x89, 0x0f };


    private byte[] iv = new byte[] { (byte)0xf0, (byte)0xc1, 0x02, 0x03, (byte)0xf4, 0x05, 0x01, 0x07, 0x0d, (byte)0x99, 0x11, 0x12, 0x11, 0x00, 0x33, 0x32 };

    private String plaintexts; 
    private StringBuilder plaintext1 = new StringBuilder();;
    private StringBuilder plaintext2 = new StringBuilder();
   

    public  byte[] hexStringToByteArray(String s) {
	int len = s.length();
	byte[] data = new byte[len / 2];
	for (int i = 0; i < len; i += 2) {
	    data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
				  + Character.digit(s.charAt(i+1), 16));
	}
	return data;
    }
    


    
    public PseudoRandomOracleHelper(String plaintexts) {
        this.plaintexts = plaintexts;
	parseOutPlaintexts(plaintexts);

    }


    void parseOutPlaintexts(String plaintexts) {
	int i=0;
	for(i=0;i<32;i++) 
	    plaintext1.append(plaintexts.charAt(i));
	for(i=32;i<64;i++) 
	    plaintext2.append(plaintexts.charAt(i));
    }


    public String getPlaintext1() { 
	return plaintext1.toString(); 
    }


    /*
    public void linkUnlink() {
	

	byte[] ext = new byte[24];
	new Random().nextBytes(ext);	
	String fileName = "newFile" + ext.toString();
	File file = new File(fileName);

	

	try {
	    if (file.createNewFile()) {
		System.out.println("File named " + fileName
				   + " created successfully !");
		PrintWriter writer = new PrintWriter(file);
		writer.print("This is a string");
		writer.close();

	    } else {
		System.out.println("File with name " + fileName
				   + " already exixts !");
	    }
	} catch (IOException e) {
	    e.printStackTrace();
	}


	try {
	    
	    if (file.delete()) {
		System.out.println("File deleted successfully !");
	    } else {
		System.out.println("File delete operation failed !");
	    }

	} catch (Exception e) {
	    e.printStackTrace();
	}



	
    }
    */
    

    public String getPlaintext2() { 

	return plaintext2.toString(); 

    }


    public String getCipherText() { 
	int  randomCoin;
	//int random = (int )(Math.random() * 50 + 1);
	//linkUnlink();
	//randomCoin=random%2;
	randomCoin=0;
	String _str = "";
	if(randomCoin==0) {
	    
	    for(int i=0 ; i < 120 ; i++) {
		
		_str = oracleEncrypt(plaintext1.toString());
		
	    }
	}

	else {

	    for(int i=0 ; i < 120 ; i++) {
		
		_str = oracleEncrypt(plaintext2.toString());
		
	    }

	    
	}

	return _str;
    }


    private  String oracleEncrypt(String plaintext) {

	try {
	    //byte[] iv = new byte[16];
	    //new Random().nextBytes(iv);
	    SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
	    IvParameterSpec ivSpec = new IvParameterSpec(iv);
	    Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
	    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);  
	    byte[] tmp = hexStringToByteArray(plaintext);
	    byte [] ciphertext = cipher.doFinal(tmp);
	    
	    
	    //String retVal = javax.xml.bind.DatatypeConverter.printHexBinary(ciphertext) + "|" + new Integer(ciphertext.length);
	    //return retVal;
	    return javax.xml.bind.DatatypeConverter.printHexBinary(ciphertext);
	}
	catch(BadPaddingException ex)
	    {
		System.out.println(" Bad Padding exception");
	    }

	catch( InvalidKeyException ex)
	    {
		System.out.println("Invalid key exception");
	    }
	catch( InvalidAlgorithmParameterException ex)
	    {
		System.out.println("InvalidAlgorithmParameterException exception");
	    }
	catch( NoSuchAlgorithmException ex)
	    {
		System.out.println("No such algorithm exception");
	    }
	catch( IllegalBlockSizeException ex)
	    {
		System.out.println("Illegal block size exception");
	    }
	catch(NoSuchPaddingException ex)
	    {
		System.out.println("No such padding exception");
	    }
	return "Error";
    }


}
