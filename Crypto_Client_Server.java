import java.net.*;
import java.util.Random;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Mac;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import javax.crypto.spec.DESKeySpec;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
public class Crypto_Client_Server {
	static  byte[] IV = new byte[8];
	static int SessionID=0;
	static int MIM=0;
	static int S ;
	static String Key1,Key2;
/* Cryptographic Functions:-
	 * Triple DES Encryption-Decryption
	 * CBC Integrity Check
	 * CFB Encryption-Decryption
	 * PCBC Encryption-Decryption-Integriy Check
	 * RC4 Encryption-Decryption
	 * RSA Encryption-Decryption
	 * HMAC Hash Function
*/
	public static byte[] TRIPLE_DES_Encrypt_Byte (String Input, SecretKey Key1, SecretKey Key2) throws Exception
	{
	Cipher m_encrypter = Cipher.getInstance("DES/ECB/NoPadding");
	Cipher m_decrypter = Cipher.getInstance("DES/ECB/NoPadding");
	m_encrypter.init(Cipher.ENCRYPT_MODE, Key1);
	m_decrypter.init(Cipher.DECRYPT_MODE, Key2);
	byte[] clearText = Input.getBytes();
	byte[] encryptedText1 = m_encrypter.doFinal(clearText);
	byte[] decryptedText1 = m_decrypter.doFinal(encryptedText1);
	byte[] encryptedText = m_encrypter.doFinal(decryptedText1);
	return encryptedText;
	}
	public static String TRIPLE_DES_Decrypt_Byte (byte[] Input, SecretKey Key1, SecretKey Key2) throws Exception
	{
	String Output;
	Cipher m_encrypter = Cipher.getInstance("DES/ECB/NoPadding");
	Cipher m_decrypter = Cipher.getInstance("DES/ECB/NoPadding");
	m_decrypter.init(Cipher.DECRYPT_MODE, Key1);
	m_encrypter.init(Cipher.ENCRYPT_MODE, Key2);
	byte[] decryptedText2 = m_decrypter.doFinal(Input);
	byte[] encryptedText2 = m_encrypter.doFinal(decryptedText2);
	byte[] decryptedText = m_decrypter.doFinal(encryptedText2);
	Output=new String(decryptedText);
	return Output;
	}
	public static String TRIPLE_DES_Encrypt_Hash (String Input) throws Exception
	{
		while((Input.getBytes()).length%8!=0)	
		Input = Input + "0";
		DESKeySpec desKeySpec = new DESKeySpec(Key1.getBytes());
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
        SecretKey KEY1 = keyFactory.generateSecret(desKeySpec);
        DESKeySpec desKeySpec1 = new DESKeySpec(Key2.getBytes());
        SecretKeyFactory keyFactory1 = SecretKeyFactory.getInstance("DES");
        SecretKey KEY2 = keyFactory1.generateSecret(desKeySpec1);
		Cipher m_encrypter = Cipher.getInstance("DES/ECB/NoPadding");
		Cipher m_decrypter = Cipher.getInstance("DES/ECB/NoPadding");
		m_encrypter.init(Cipher.ENCRYPT_MODE, KEY1);
		m_decrypter.init(Cipher.DECRYPT_MODE, KEY2);
		byte[] clearText = Input.getBytes();
		byte[] encryptedText1 = m_encrypter.doFinal(clearText);
		byte[] decryptedText1 = m_decrypter.doFinal(encryptedText1);
		byte[] encryptedText = m_encrypter.doFinal(decryptedText1);
		return (new String (encryptedText));
	}
	public static String CBC_Integrity(String Input, byte[] IV, SecretKey Key1, SecretKey Key2) throws Exception
	{
		String InputBlock;
		byte[] ClearText,EncryptedText = {(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00};
		Cipher m_encrypter = Cipher.getInstance("DES/ECB/NoPadding");
		Cipher m_decrypter = Cipher.getInstance("DES/ECB/NoPadding");
		m_encrypter.init(Cipher.ENCRYPT_MODE, Key1);
		m_decrypter.init(Cipher.DECRYPT_MODE, Key2);
		int PAD = Input.length() % 8;
		if (PAD !=0)
		{
			for (int i=0;i<8-PAD;i++)
				Input = Input + "0";
		}
		int Blocks=Input.length()/8;
		for (int i=0;i<Blocks;i++)
		{
			InputBlock =Input.substring(i*8, (i*8)+8);
			ClearText = InputBlock.getBytes();
			if (i==0)
			{
				ClearText = XOR (ClearText,IV,8);
			}
			else
			{
				ClearText = XOR (ClearText,EncryptedText,8);
			}
			EncryptedText = TRIPLE_DES_Encrypt_Byte(ClearText,Key1,Key2);
		}
		return (new String(EncryptedText));
	}
	public static byte[] CFB_Encrypt (String Input, byte[] iv, SecretKey Key1, SecretKey Key2, int k) throws Exception
	{
		String RoundInputMessage, EncryptedMessage;
		byte[] K_bytes = new byte [k], RoundIV = new byte [8], FeedBack = new byte [k],RoundEncryptionOutput, RoundInputMessageBytes,Output = new byte [Input.length()];
		System.arraycopy(iv, 0, RoundIV, 0, 8);
		for (int i =0; i<Input.length() / k; i++)
		{
			RoundEncryptionOutput = TRIPLE_DES_Encrypt_Byte(RoundIV, Key1, Key2);
			System.arraycopy(RoundEncryptionOutput, 0, K_bytes, 0, k); 
			RoundInputMessage = Input.substring((k*i),k*(i+1));
			RoundInputMessageBytes = RoundInputMessage.getBytes();
			FeedBack = XOR (RoundInputMessageBytes,K_bytes,k);
			System.arraycopy(FeedBack,0,Output,k*i,k);
			for (int j=0;j<8-k;j++)
			{
				iv[j] = iv[j+k];
			}
			System.arraycopy(FeedBack,0,iv,8-k,k);
			System.arraycopy(iv, 0, RoundIV, 0, 8);
		}
		EncryptedMessage = new String (Output);
		return Output;
	}
	public static String CFB_Decrypt (byte[] Input, byte[] iv, SecretKey Key1, SecretKey Key2, int k) throws Exception
    {
    	String DecryptedMessage;
    	byte[] K_bytes = new byte [k],RoundIV = new byte [8], FeedBack = new byte [k],RoundEncryptionOutput, RoundOutputBytes, RoundInputMessageBytes= new byte [k],Output = new byte [Input.length];
    	System.arraycopy(iv, 0, RoundIV, 0, 8);
    	for (int i =0; i<Input.length / k; i++)
    	{
    		RoundEncryptionOutput = TRIPLE_DES_Encrypt_Byte(RoundIV, Key1, Key2);
    		System.arraycopy(RoundEncryptionOutput, 0, K_bytes, 0, k);
    		System.arraycopy(Input,k*i,RoundInputMessageBytes,0,k);
    		RoundOutputBytes = XOR (RoundInputMessageBytes,K_bytes,k);
    		System.arraycopy(RoundOutputBytes,0,Output,k*i,k);
    		System.arraycopy(RoundInputMessageBytes,0,FeedBack,0,k);
    		for (int j=0;j<8-k;j++)
    		{
    			iv[j] = iv[j+k];
    		}
    		System.arraycopy(FeedBack,0,iv,8-k,k);
    		System.arraycopy(iv, 0, RoundIV, 0, 8);
    	}
    	DecryptedMessage = new String (Output);
    	return DecryptedMessage;
    }
    public static byte[] XOR(byte[] Input1, byte[] Input2, int length) throws Exception
	{
		byte[] Result = new byte[length];
		for(int i=0;i<length;i++) 
		{
			Result[i]=(byte)(Input1[i]^Input2[i]);
		}
		return Result;
	}
	public static byte[] TRIPLE_DES_Encrypt  (String Input, SecretKey Key1, SecretKey Key2) throws Exception
	{
		Cipher m_encrypter = Cipher.getInstance("DES/ECB/NoPadding");
		Cipher m_decrypter = Cipher.getInstance("DES/ECB/NoPadding");
		m_encrypter.init(Cipher.ENCRYPT_MODE, Key1);
		m_decrypter.init(Cipher.DECRYPT_MODE, Key2);
		byte[] clearText = Input.getBytes();
		byte[] encryptedText1 = m_encrypter.doFinal(clearText);
		byte[] decryptedText1 = m_decrypter.doFinal(encryptedText1);
		byte[] encryptedText = m_encrypter.doFinal(decryptedText1);
		return encryptedText;
	}
	public static byte[] TRIPLE_DES_Encrypt_Byte  (byte[] Input, SecretKey Key1, SecretKey Key2) throws Exception
	{
		Cipher m_encrypter = Cipher.getInstance("DES/ECB/NoPadding");
		Cipher m_decrypter = Cipher.getInstance("DES/ECB/NoPadding");
		m_encrypter.init(Cipher.ENCRYPT_MODE, Key1);
		m_decrypter.init(Cipher.DECRYPT_MODE, Key2);
		byte[] encryptedText1 = m_encrypter.doFinal(Input);
		byte[] decryptedText1 = m_decrypter.doFinal(encryptedText1);
		byte[] encryptedText = m_encrypter.doFinal(decryptedText1);
		return encryptedText;
	}
	public static String PCBC_Integrity (String Input, byte[] iv, SecretKey Key1, SecretKey Key2) throws Exception
	{
		String EncryptionInputMessage, Output="";
		byte[] InputBytes = Input.getBytes(), RoundEncryptionOutput,RoundXOROutput, RoundInputMessageBytes = new byte [8];
		byte[] RoundFeed = new byte [8];
		System.arraycopy(iv,0,RoundFeed,0,8);
		for (int i = 0; i<InputBytes.length / 8; i++)
		{
			System.arraycopy(InputBytes,i*8,RoundInputMessageBytes,0,8);
			RoundXOROutput = XOR(RoundInputMessageBytes,RoundFeed,8);
			EncryptionInputMessage =  new String (RoundXOROutput);
			RoundEncryptionOutput = TRIPLE_DES_Encrypt(EncryptionInputMessage,Key1,Key2);
			RoundFeed = XOR(RoundInputMessageBytes,RoundEncryptionOutput,8);
			Output = new String (RoundEncryptionOutput);
		}
		return Output;
	}
	public static byte[] PCBC_Encrypt(String InputMessage,byte[] IV,SecretKey Key1,SecretKey Key2) throws Exception
	{
		int pad=InputMessage.length()%8;
		for(int i=0;i<8-pad;i++)
		{
			InputMessage+="^";
		}
		InputMessage+="########";
		String RoundInputMessage="";
		byte[] RoundOutputBytes= new byte[8],EncryptedMessage = new byte [InputMessage.length()];
		for (int i = 0; i<InputMessage.length()/8;i++)
		{
			RoundInputMessage = InputMessage.substring((8*i),8*(i+1));
			RoundOutputBytes = TRIPLE_DES_Encrypt_Byte(RoundInputMessage,Key1,Key2);
			System.arraycopy(RoundOutputBytes, 0, EncryptedMessage, 8*i, 8);
		}
		return(EncryptedMessage);
	}
	public static String PCBC_Decrypt(byte[] EncryptedMessage,byte[] IV,SecretKey Key1,SecretKey Key2) throws Exception
	{
		byte[] RoundOutputBytes=new byte[8];
		String RoundOutputMessage="",TempOutputMessage="";
		for (int i = 0; i<EncryptedMessage.length/8;i++)
		{
			System.arraycopy(EncryptedMessage, 8*i, RoundOutputBytes, 0, 8);
			RoundOutputMessage = TRIPLE_DES_Decrypt_Byte(RoundOutputBytes,Key1,Key2);
			TempOutputMessage = TempOutputMessage + RoundOutputMessage;
		}
		String Checksum=TempOutputMessage.substring(TempOutputMessage.length()-8, TempOutputMessage.length());
		TempOutputMessage=TempOutputMessage.substring(0,TempOutputMessage.length()-8);
		if(Checksum.equals("########")) {
			int done=0;
			while(done!=1) {
				if(TempOutputMessage.lastIndexOf('^')==TempOutputMessage.length()-1) {
					TempOutputMessage=TempOutputMessage.substring(0,TempOutputMessage.length()-1);
				}
				else {
					done=1;
				}
			}
		}
		return(TempOutputMessage);
	}
	public static String TRIPLE_DES_Decrypt  (byte[] Input, SecretKey Key1, SecretKey Key2) throws Exception
	{   
		String Output;	
		Cipher m_encrypter = Cipher.getInstance("DES/ECB/NoPadding");
		Cipher m_decrypter = Cipher.getInstance("DES/ECB/NoPadding");
		m_decrypter.init(Cipher.DECRYPT_MODE, Key1);
		m_encrypter.init(Cipher.ENCRYPT_MODE, Key2);
		byte[] decryptedText2 = m_decrypter.doFinal(Input);
		byte[] encryptedText2 = m_encrypter.doFinal(decryptedText2);
		byte[] decryptedText = m_decrypter.doFinal(encryptedText2);
		Output=new String(decryptedText);
		return Output;
	}
	public static String RC4_Decrypt (byte[] InputBytes, byte[] OTPad) throws Exception
	{
		int LengthInput = InputBytes.length , LengthOTP = OTPad.length;
		byte[] Output = new byte [LengthInput],TempOutput, TempInput  = new byte [LengthOTP];
		for (int i=0; i<LengthInput/LengthOTP;i++)
		{
			System.arraycopy(InputBytes, i*LengthOTP, TempInput, 0, LengthOTP);
			TempOutput = XOR(TempInput,OTPad,LengthOTP);
			System.arraycopy(TempOutput, 0, Output, i*LengthOTP, LengthOTP);
		}
		return (new String(Output));
	}
	public static byte[] RC4_Encrypt (String Input, byte[] OTPad) throws Exception
	{	
		byte[] InputBytes = Input.getBytes("UTF-8");
		int LengthInput = InputBytes.length , LengthOTP = OTPad.length;
		byte[] Output = new byte [LengthInput],TempOutput, TempInput  = new byte [LengthOTP];
		for (int i=0; i<LengthInput/LengthOTP;i++)
		{
			System.arraycopy(InputBytes, i*LengthOTP, TempInput, 0, LengthOTP);
			TempOutput = XOR(TempInput,OTPad,LengthOTP);
			System.arraycopy(TempOutput, 0, Output, i*LengthOTP, LengthOTP);
		}
		return (Output);
	}
	public static BigInteger Getd(BigInteger p, BigInteger q,BigInteger e,BigInteger n)
    {
        BigInteger one = new BigInteger("1");
        BigInteger m=(p.subtract(one)).multiply(q.subtract(one));
        BigInteger d = e.modInverse(m);
        return (d);
    }
    public static String RSA_Encrypt(String plainText, BigInteger e, BigInteger n)
    {
        String encrypted = "";
        int j = 0;
        for(int i = 0; i < plainText.length(); i++){
            char m = plainText.charAt(i);
            BigInteger bi1 = BigInteger.valueOf(m);
            BigInteger bi2 = bi1.modPow(e, n);
            j = bi2.intValue();
            m = (char) j;
            encrypted += m;
        }
        return encrypted;
    }
    public static String RSA_Decrypt(String cipherText, BigInteger d, BigInteger n)
    {
        String decrypted = "";
        int j = 0;
        for(int i = 0; i < cipherText.length(); i++){
            char c = cipherText.charAt(i);
            BigInteger bi1 = BigInteger.valueOf(c);
            BigInteger bi2 = bi1.modPow(d, n);
            j = bi2.intValue();
            c = (char) j;
            decrypted += c;
        }
        return decrypted;
    }
	public static String HMAC(String Input, String Key) 
	{
        try {
            byte[] ByteKey = Key.getBytes("UTF-8");  
            byte[] ByteInput = Input.getBytes("UTF-8");  
            SecretKey Secret = new SecretKeySpec(ByteKey, "HmacMD5");
            Mac mac = Mac.getInstance("HmacMD5");
            mac.init(Secret);
            byte[] Output = mac.doFinal(ByteInput);
            return new String(Output, "UTF-8");      
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }	
/* End of Crypto Functions*/
	

/* File Transfer Functions - sendFile and receiveFile */
	public static void sendFile(ServerSocket serverSocket, Socket server,String cipher) throws Exception{
		String fileToSend = "";
        while (true) {
            BufferedOutputStream outToClient = null;
            try {
                DataInputStream in = new DataInputStream(server.getInputStream());
                fileToSend=in.readUTF();
                outToClient = new BufferedOutputStream(server.getOutputStream());
            } 
            catch (IOException ex) {
            	ex.printStackTrace();
            }
            if (outToClient != null) {
                File myFile = new File(fileToSend);
                byte[] mybytearray = new byte[(int) myFile.length()];
                FileInputStream fis = null;
                try {
                    fis = new FileInputStream(myFile);
                } 
                catch (FileNotFoundException ex) {
                	System.out.println("File - "+fileToSend+ " does not exist");
                	cipher="null";
                }
                BufferedInputStream bis = new BufferedInputStream(fis);
                try {
                    bis.read(mybytearray, 0, mybytearray.length);
                    if(cipher.equals("3DES/CFB for encryption")){
                    	String InputMessage=new String(mybytearray);
                        int PAD = InputMessage.length() % 1;
                        if (PAD !=0)
                        {
                                for (int i=0;i<8-PAD;i++) {
                                InputMessage = InputMessage + "0";
                            }
                        }
                        byte[] RoundOutputBytes= new byte[8],EncryptedMessage = new byte [InputMessage.length()];
                        DESKeySpec desKeySpec = new DESKeySpec(Key1.getBytes());
                        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
                        SecretKey KEY1 = keyFactory.generateSecret(desKeySpec);
                        DESKeySpec desKeySpec1 = new DESKeySpec(Key2.getBytes());
                        SecretKeyFactory keyFactory1 = SecretKeyFactory.getInstance("DES");
                        SecretKey KEY2 = keyFactory1.generateSecret(desKeySpec1);
                        byte[] EncryptionOutput = CFB_Encrypt (InputMessage, IV, KEY1,KEY2,1);
                        outToClient.write(EncryptionOutput, 0, EncryptionOutput.length);
                        System.out.println("Encrypted Data to be transferred :- \n"+new String(EncryptionOutput));
                    }
                    else if(cipher.equals("3DES/CBC for integrity protection")){
                        String InputMessage=new String(mybytearray,"UTF-8");
                    	DESKeySpec desKeySpec = new DESKeySpec(Key1.getBytes());
                        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
                        SecretKey KEY1 = keyFactory.generateSecret(desKeySpec);
                        DESKeySpec desKeySpec1 = new DESKeySpec(Key2.getBytes());
                        SecretKeyFactory keyFactory1 = SecretKeyFactory.getInstance("DES");
                        SecretKey KEY2 = keyFactory1.generateSecret(desKeySpec1);
                        String temp=CBC_Integrity(InputMessage,IV,KEY1,KEY2);
                        InputMessage=InputMessage+"-1"+temp;
                        outToClient.write(InputMessage.getBytes(), 0, InputMessage.getBytes().length);
                        System.out.println("Data to be transferred :- \n"+InputMessage);
                    }
                    else if(cipher.equals("3DES/PCBC for encryption and integrity protection")){
                    	String InputMessage=new String(mybytearray,"UTF-8");
                    	byte[] EncryptedMessage;
                    	DESKeySpec desKeySpec = new DESKeySpec(Key1.getBytes());
                    	SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
                    	SecretKey Key1 = keyFactory.generateSecret(desKeySpec);
                    	DESKeySpec desKeySpec1 = new DESKeySpec(Key2.getBytes());
                    	SecretKeyFactory keyFactory1 = SecretKeyFactory.getInstance("DES");
                    	SecretKey Key2 = keyFactory1.generateSecret(desKeySpec1);
                    	EncryptedMessage = PCBC_Encrypt(InputMessage, IV, Key1, Key2);
                    	outToClient.write(EncryptedMessage, 0, EncryptedMessage.length);
                    	System.out.println("Encrypted Data to be transferred :- \n"+new String(EncryptedMessage));
                    	}
                    else if(cipher.equals("Implement RC4 for encryption")){
        	    		String InputMessage=new String(mybytearray);
        	    		byte [] Encryption; 
        	    		int PAD; 
        	    		PAD = InputMessage.length() % 8;
        	    		if (PAD !=0)
        	    		{
        	    			InputMessage = InputMessage + "#";
        	    			for (int i=1;i<8-PAD;i++) 
        	    				InputMessage = InputMessage + "0";
        	    		}
        	    		Encryption = RC4_Encrypt(InputMessage,IV);
        	    		outToClient.write(Encryption, 0, Encryption.length);
        	    		System.out.println("Encrypted Data to be transferred :- \n"+new String(Encryption));
        	    	}
                    else{
                    	byte[] error_msg="File Not Found".getBytes();
                    	outToClient.write(error_msg,0,error_msg.length);
                    }
        	    	outToClient.flush();
                    outToClient.close();
                    server.close();
                    System.out.println("Response sent");
                    return;
                } catch (IOException ex) {
                	ex.printStackTrace();
                }
            }
        }
	}
	public static void receiveFile(Socket client,String cipher) throws Exception{
    	InputStream is = null;
        OutputStream os = null;
        Scanner user_input = new Scanner( System.in );
        String filename ;
        System.out.println("Enter the name of file you want from the server:");
        filename = user_input.next();
        byte[] aByte = new byte[1];
        int bytesRead;
    	try {
    	    os=client.getOutputStream();
    	    is = client.getInputStream();
    	}
    	catch (IOException ex) {
    	    ex.printStackTrace();
    	}
        DataOutputStream out =new DataOutputStream(os);
    	try {
    		out.writeUTF(filename);
    	}
    	catch (IOException e) {
    	    e.printStackTrace();
    	}
    	ByteArrayOutputStream baos = new ByteArrayOutputStream();
    	if (is != null) {
    	    FileOutputStream fos = null;
    	    BufferedOutputStream bos = null;
    	    try {
    	    	fos = new FileOutputStream(filename);
    	    	bos = new BufferedOutputStream(fos);
    	    	bytesRead = is.read(aByte, 0, aByte.length);
    	    	do {
    	    		baos.write(aByte);
    	    		bytesRead = is.read(aByte);
    	    	} while (bytesRead != -1);
    	    	byte[] EncryptionOutput=baos.toByteArray();
    	    	if(MIM==1){
    	    		Random randomNo=new Random();
    	    		int index=randomNo.nextInt(EncryptionOutput.length);
    	    		EncryptionOutput[index]+=1;
			index=randomNo.nextInt(EncryptionOutput.length);
			EncryptionOutput[index]+=1;
			index=randomNo.nextInt(EncryptionOutput.length);
			EncryptionOutput[index]-=1;
			index=randomNo.nextInt(EncryptionOutput.length);
			EncryptionOutput[index]-=1;
    	    	}
    	    	if(new String(EncryptionOutput)=="File Not Found")
    	    		System.out.println("Server cannot find a file named: "+filename);
    	    	else{
    	    	System.out.println("Client Received Data :-\n"+new String(EncryptionOutput));
    	    	DESKeySpec desKeySpec = new DESKeySpec(Key1.getBytes());
                SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
                SecretKey KEY1 = keyFactory.generateSecret(desKeySpec);
                DESKeySpec desKeySpec1 = new DESKeySpec(Key2.getBytes());
                SecretKeyFactory keyFactory1 = SecretKeyFactory.getInstance("DES");
                SecretKey KEY2 = keyFactory1.generateSecret(desKeySpec1);
    	    	if(cipher.equals("3DES/CFB for encryption")){
    	    		byte[] RoundOutputBytes= new byte[8];
                    String TempOutputMessage = "", OutputMessage, RoundOutputMessage;
                    String DecryptionOutput = CFB_Decrypt (EncryptionOutput, IV, KEY1,KEY2,1);
                    bos.write(DecryptionOutput.getBytes());
   	    		 	System.out.println("File Transfer Complete");
    	    	}
    	    	else if(cipher.equals("3DES/CBC for integrity protection")){
    	    		String Input=new String(EncryptionOutput);
    	    	    String InputBlock,cbc_r;
    	    	    int index=Input.indexOf("-1");
    	    	    InputBlock =Input.substring(0,index);
    	    	    cbc_r =Input.substring((index+2), Input.length());
    	    	    String temp=CBC_Integrity(InputBlock,IV,KEY1,KEY2);
    	    	    if(temp.equals(cbc_r)==true){
    	    	    	System.out.println("The File has not been modified");
    	    	    }
    	    	    else{
    	    	    	System.out.println("WARNING: The File has been modified");
    	    	    }
    	    	    bos.write(InputBlock.getBytes());
   	    		 	System.out.println("File Transfer Complete");
    	    	}
    	    	else if(cipher.equals("3DES/PCBC for encryption and integrity protection")){
    	    		String DecryptedMessage = PCBC_Decrypt(EncryptionOutput, IV, KEY1, KEY2);
    	    		bos.write(DecryptedMessage.getBytes());
   	    		 	System.out.println("File Transfer Complete");
    	    	}
                else if(cipher.equals("Implement RC4 for encryption")){
    	    		 String Input = new String(EncryptionOutput);
    	    		 String  DecryptionOutput,OutputMessage;
    	    		 DecryptionOutput = RC4_Decrypt(EncryptionOutput,IV);
    	    		 int index=DecryptionOutput.indexOf("#");
     	    	         if(index==-1) {
                             OutputMessage =new String (DecryptionOutput);
                         }
                         else {
                        	 OutputMessage =DecryptionOutput.substring(0,index);
                         }
    	    		 bos.write(OutputMessage.getBytes());
    	    		 System.out.println("File Transfer Complete");
    	    	}    	    	
    	    	bos.flush();
    	    	bos.close();
    	    	
    	    }
    	    }
    	    catch (IOException ex) {
    	    	ex.printStackTrace();
    	    }
    	}
    }
/* End of File Transfer Functions */
	

/* Client and Server Implementaion - Session Initiation and Session Resumption */
	public static void Client_Initial(String Server_Name, int port,String Ciphers, int Ralice) throws Exception
	{
    	Random rand = new Random();
    	int Rbob;
    	BigInteger e,n;
		String[] HS1 = new String[2], HS2=new String[2], SHS1, ServerCert;
		String Cipher, KeyTemp, HandShake,KeyedHash;
		try
		{
		Socket Client = new Socket(Server_Name, port);
		Client.setSoTimeout(30000);
		System.out.println("Connected to "+ Client.getRemoteSocketAddress() + " !!");
		OutputStream outToServer = Client.getOutputStream();
		ObjectOutput outObject = new ObjectOutputStream(outToServer);
		HS1[0]= Ciphers;
		HS1[1]= Integer.toString(Ralice);
		outObject.writeObject(HS1);
		System.out.println("Client Sent : " + HS1[0] + " || " + HS1[1]);
		HandShake = HS1[0] + HS1[1];
		System.out.println("Wait for Server's response...");
		InputStream inFromServer = Client.getInputStream();
		ObjectInputStream in =new ObjectInputStream(inFromServer);
		SHS1 = (String [])in.readObject();
		HandShake = HandShake + SHS1[0] +  SHS1[1] + SHS1[2] + SHS1[3];
		System.out.println("Client Received : "+ SHS1[0] + " || "+ SHS1[1] + " || "+ SHS1[2] + " || "+ SHS1[3] );
		SessionID=Integer.valueOf(SHS1[0]);
		Rbob = Integer.valueOf(SHS1[3]);
		ServerCert = SHS1[1].split(",");
		e = new BigInteger (ServerCert[0]);
		n = new BigInteger (ServerCert[1]);
		Cipher = new String (SHS1[2]);
		S = rand.nextInt(10000)+ 1; 
		HS2[0]= RSA_Encrypt(Integer.toString(S),e,n);
		KeyTemp = Integer.toString(S)+Integer.toString(Ralice)+Integer.toString(Rbob);
		Key1 = HMAC(KeyTemp,Integer.toString(SessionID));
		KeyTemp = Integer.toString(S)+Integer.toString(Rbob)+Integer.toString(Ralice);
		Key2 = HMAC(KeyTemp,Integer.toString(SessionID));
		KeyedHash = HMAC(HandShake,Key1);
		KeyedHash = HandShake + KeyedHash; 
	    KeyedHash = HMAC(KeyedHash,Key2);
	    HS2[1]= new String (KeyedHash);
	    outObject.writeObject(HS2);
	    HandShake = HandShake + HS2[0] + HS2[1];
		System.out.println("Client Sent : " + HS2[0] + " || " + HS2[1]);
		String[] SHS2 = (String [])in.readObject();
		System.out.println("Client Received : "+ SHS2[0]);
		if (SHS2[0].equals("The Keyed Hash do not match"))
		{
			SessionID = 0;
		}
		else {
			KeyedHash = HMAC(HandShake,Key1);
			KeyedHash = HandShake + KeyedHash; 
			KeyedHash = HMAC(KeyedHash,Key2);
			if(KeyedHash.equals(SHS2[0]))
			{
				String[] HS3 = new String[1];
			    HS3[0]  = new String ("Handshake Complete");
			    outObject.writeObject(HS3);
	  			System.out.println("Client Sent : " + HS3[0]);
	  			HandShake = HandShake + HS3[0];	
	  			receiveFile(Client,Cipher);
	  		}
			else 
			{
			    String[] HS3 = new String[1];
	  	  		HS3[0]  = new String ("The Keyed Hash do not match");
	  	  		outObject.writeObject(HS3);
	  	  		System.out.println("Client Sent : " + HS3[0]);
	  	  		SessionID = 0;
	  	  		HandShake = HandShake + HS3[0];
	  	  	}
		}      
		System.out.println("Closing Client Socket !!");
		Client.close();
		}catch(SocketTimeoutException s)
		{
			SessionID=0;
			System.out.println("Socket timed out!!");
		}catch(IOException e1)
		{
			SessionID=0;
			e1.printStackTrace();
		}
	}
    public static void Client_Resume(String Server_Name, int port, String Ciphers, int Ralice) throws Exception
  	{
    	int Rbob ;
    	String Cipher, HandShake, KeyedHash, KeyTemp;
		String[] HS1 = new String[3], HS2=new String[1], SHS1;
		try
		{
		Socket Client = new Socket(Server_Name, port);
		Client.setSoTimeout(30000);
		System.out.println("Connected to "+ Client.getRemoteSocketAddress() + " !!");
		OutputStream outToServer = Client.getOutputStream();
		ObjectOutput outObject = new ObjectOutputStream(outToServer);
		HS1[0]= Integer.toString(SessionID);
		HS1[1]= Ciphers;
		HS1[2]= Integer.toString(Ralice);
		outObject.writeObject(HS1);
		HandShake =  HS1[0] + HS1[1] + HS1[2];
		System.out.println("Client Sent : " + HS1[0] + " || " + HS1[1] + " || " + HS1[2] );
		System.out.println("Wait for Server's Response...");
		InputStream inFromServer = Client.getInputStream();
		ObjectInputStream in =new ObjectInputStream(inFromServer);
		SHS1 = (String[])in.readObject();
		if(SHS1.length == 4)
		{
			  KeyTemp = new String ("Key1");
		      KeyedHash = HMAC(HandShake,KeyTemp);
		      KeyedHash = HandShake + KeyedHash; 
		      KeyTemp = new String ("Key2");
		      KeyedHash = HMAC(KeyedHash,KeyTemp);
		      if (KeyedHash.equals(SHS1[3]))
		      {
					  HandShake =  HandShake + SHS1[0] + SHS1[1]+ SHS1[2] + SHS1[3]; 
					  System.out.println("Client Received : " + SHS1[0] + " || " + SHS1[1] + " || " + SHS1[2] + " || " + SHS1[3]);
					  Cipher = new String (SHS1[1]);
					  Rbob = Integer.valueOf(SHS1[2]);
					  KeyTemp = new String ("Key1");
				      KeyedHash = HMAC(HandShake,KeyTemp);
				      KeyedHash = HandShake + KeyedHash; 
				      KeyTemp = new String ("Key2");
				      KeyedHash = HMAC(KeyedHash,KeyTemp);
				      HS2[0] = new String (KeyedHash);
				      outObject.writeObject(HS2);
				      HandShake =  HandShake+HS2[0];
					  System.out.println("Client Sent : " + HS2[0] );
					  SHS1 = (String[])in.readObject();
					  System.out.println("Client Received : " + SHS1[0] );
					  if (SHS1[0].equals("Handshake Complete"))
					  {
						  receiveFile(Client,Cipher);
					  }
					  else
					  {
						  SessionID=0;
						  System.out.println("Closing Client Socket !!"); 
					  }
		      }
		      else
		      {
		    	  HS2[0] = new String ("The Keyed Hash do not match");
		    	  System.out.println("Client Sent : " + HS2[0] );
		    	  SessionID=0;
		    	  System.out.println("Closing Client Socket !!");
		      }
		}
		else
		{
			System.out.println("Client Received : "+ SHS1[0]);
			System.out.println("Closing Client Socket And Reinitializing The Connection !!");
			Client.close();
			Client_Initial(Server_Name,port,Ciphers,Ralice);
		}
		Client.close();
		}catch(SocketTimeoutException s)
		{
			SessionID=0;
			System.out.println("Socket timed out!!");
			
		}catch(IOException e)
		{
			SessionID=0;
			e.printStackTrace();
			
		} catch (ClassNotFoundException f) {
			SessionID=0;
			f.printStackTrace();
		}
  	}
    public static void Server(int port) throws Exception
    {
    	Random rand = new Random();
    	int SessionID = 10;
    	int Ralice,Rbob = rand.nextInt(10000)+ 1;
    	BigInteger p=new BigInteger("11");
    	BigInteger q=new BigInteger("23");
    	BigInteger e=new BigInteger("3");
    	BigInteger n = p.multiply(q);
    	BigInteger d=Getd(p,q,e,n);
    	ServerSocket serverSocket;
    	serverSocket = new ServerSocket(port);
    	serverSocket.setSoTimeout(120000);
    	Scanner user_input = new Scanner (System.in);
    	String Cipher = null,HandShake,KeyedHash, KeyTemp;
    	int Choice = 0, InputArrayLength=0;
    	String[] CHS1,CHS2 ,HS1 = null,Ciphers;
    	System.out.println("Server Started on PORT : " +serverSocket.getLocalPort() + "!!");
    	while(true)
    	{
    		System.out.println("Waiting For Client to Connect !!!...");
    		try
    		{
    			Socket server = serverSocket.accept();
    			ObjectInput In=new ObjectInputStream(server.getInputStream());
    			ObjectOutput out =new ObjectOutputStream(server.getOutputStream());
    			CHS1=(String[])In.readObject();
    			if( CHS1.length == 2)
    			{
    				System.out.println("Server Received : " + CHS1[0]+" || " + CHS1[1]);
    				HandShake = CHS1[0]+CHS1[1];
    				Ralice = Integer.valueOf(CHS1[1]);
    				Ciphers = CHS1[0].split(",");
    				InputArrayLength = Ciphers.length;
    				System.out.println("Available Cipher Modes :-");
    				for(int i=0; i<= InputArrayLength;i++)
    				{
    					if (i<InputArrayLength)
    						System.out.println(i+1+") "+Ciphers[i]);
    					/*
    					else
    						System.out.println(i+1+") Exit ");
    					*/
    				}
    				Choice= InputArrayLength+1;
    				while (Choice == InputArrayLength+1 )
    				{
    					System.out.println("Enter Choice : ");
    					Choice = user_input.nextInt();
    					if (Choice<=InputArrayLength)
    						Cipher = Ciphers[Choice-1];
    					if (Choice>InputArrayLength)
    						System.out.println("Please Enter Correct Choice");
    				}
    				HS1 = new String[4];
    				HS1[0] = Integer.toString(SessionID);
    				String temp_PK = e.toString()+ "," + n.toString();
    				HS1[1]= new String(temp_PK);
    				HS1[2]= new String(Cipher);
    				HS1[3]= Integer.toString(Rbob);
    				out.writeObject(HS1);
    				HandShake = HandShake + HS1[0] + HS1[1] + HS1[2] + HS1[3];
    				System.out.println("Server Sent : "+ HS1[0] + " || " + HS1[1] + " || "+ HS1[2] + " || " + HS1[3]);
    				CHS2=(String[])In.readObject();
    				System.out.println("Server Received : " + CHS2[0]+ " || " + CHS2[1]);
    				String S_string = RSA_Decrypt(CHS2[0],d,n);
    				S = Integer.valueOf(S_string);
    				KeyTemp = Integer.toString(S)+Integer.toString(Ralice)+Integer.toString(Rbob);
    				Key1 = HMAC(KeyTemp,Integer.toString(SessionID));
    				KeyTemp = Integer.toString(S)+Integer.toString(Rbob)+Integer.toString(Ralice);
    				Key2 = HMAC(KeyTemp,Integer.toString(SessionID));
    				KeyedHash = HMAC(HandShake,Key1);
    				KeyedHash = HandShake + KeyedHash;
    				KeyedHash = HMAC(KeyedHash,Key2);
    				if (KeyedHash.equals(CHS2[1]))
    				{	HandShake = HandShake + CHS2[0] + CHS2[1];
    					KeyedHash = HMAC(HandShake,Key1);
    					KeyedHash = HandShake + KeyedHash;
    					KeyedHash = HMAC(KeyedHash,Key2);
    					String[] HS2 = new String [1];
    					HS2[0] = new String (KeyedHash);
    					out.writeObject(HS2);
    					HandShake = HandShake + HS2[0];
    					System.out.println("Server Sent : "+ HS2[0]);
    					String [] CHS3 = (String[])In.readObject();
    					System.out.println("Server Received : " + CHS3[0]);
    					if (CHS3[0].equals("The Keyed Hash do not match"))
    					{
    						SessionID = 0;
    						System.out.println("Server Received : The Keyed Hash do not match");
    					}
    					else
    					{
    						System.out.println("Wait for Client's request for data...");
    						sendFile(serverSocket,server,Cipher);
    					}
    				}
    				else
    				{
    					String[] HS2 = new String [1];
    					HS2[0] = new String ("The Keyed Hash do not match");
    					out.writeObject(HS2);
    					System.out.println("Server Sent : "+ HS2[0]);
    				}
    			}
    			else
    			{
    				System.out.println("Server Received : " + CHS1[0]+" || " + CHS1[1] + " || " + CHS1[2]);
    				HandShake = CHS1[0] + CHS1[1] + CHS1[2];
    				if (SessionID == Integer.valueOf(CHS1[0]))
    				{
    					Ralice = Integer.valueOf(CHS1[2]);
    					System.out.println("Session ID = "+ SessionID +" R-Alice = "+ Ralice);
    					Ciphers = CHS1[1].split(",");
    					InputArrayLength = Ciphers.length;
    					System.out.println("Available Cipher Modes :-");
    					for(int i=0; i<= InputArrayLength;i++)
    					{
    						if (i<InputArrayLength)
    							System.out.println(i+1+") "+Ciphers[i]);
    						/*
    						else
    							System.out.println(i+1+") Exit ");
    						*/
    					}
    					Choice= InputArrayLength+1;
    					while (Choice == InputArrayLength+1 )
    					{
    						System.out.println("Enter Choice : ");
    						Choice = user_input.nextInt();
    						if (Choice<=InputArrayLength)
    							Cipher = Ciphers[Choice-1];
    						if (Choice>InputArrayLength)
    							System.out.println("Please Enter Correct Choice");
    					}
    					HS1 = new String[4];
    					HS1[0] = Integer.toString(SessionID);
    					HS1[1]= new String(Cipher);
    					HS1[2]= Integer.toString(Rbob);
    					KeyTemp = new String ("Key1");
    					KeyedHash = HMAC(HandShake,KeyTemp);
    					KeyedHash = HandShake + KeyedHash;
    					KeyTemp = new String ("Key2");
    					KeyedHash = HMAC(KeyedHash,KeyTemp);
    					HS1[3]= KeyedHash;
    					out.writeObject(HS1);
    					HandShake = HandShake + HS1[0] + HS1[1] + HS1[2] + HS1[3];
    					System.out.println("Server Sent : "+ HS1[0] + " || " + HS1[1] + " || "+ HS1[2] + " || " + HS1[3]);
    					KeyTemp = new String ("Key1");
    					KeyedHash = HMAC(HandShake,KeyTemp);
    					KeyedHash = HandShake + KeyedHash;
    					KeyTemp = new String ("Key2");
    					KeyedHash = HMAC(KeyedHash,KeyTemp);
    					CHS2=(String[])In.readObject();
    					System.out.println("Server Received : " + CHS2[0]);
    					if (CHS2[0].equals("The Keyed Hash do not match"))
    					{
    						System.out.println("Closing Socket !!");
    					}
    					else
    					{
    						if (KeyedHash.equals(CHS2[0]))
    						{
    							String[] HS2 = new String [1];
    							HS2[0] = new String ("Handshake Complete");
    							out.writeObject(HS2);
    							System.out.println("Server Sent : "+ HS2[0]);
    							System.out.println("Wait for Client's request for data...");
    							sendFile(serverSocket,server,Cipher);
    						}
    						else
    						{
    							String[] HS2 = new String [1];
    							HS2[0] = new String ("The Keyed Hash do not match");
    							out.writeObject(HS2);
    							System.out.println("Server Sent : "+ HS2[0]);
    						}
    					}
    				}
    				else
    				{
    					HS1 = new String[1];
    					HS1[0]="SessionID Mismatch";
    					out.writeObject(HS1);
    					System.out.println("Server Sent : "+ HS1[0] );
    				}
    			}
    			server.close();
    		}catch(SocketTimeoutException s)
    		{
    			SessionID=0;
    			System.out.println("Socket timed out!!");
    			break;
    		}catch(IOException e1)
    		{
    			SessionID=0;
    			e1.printStackTrace();
    			break;
    		}catch (ClassNotFoundException f) {
    			SessionID=0;
    			f.printStackTrace();
    		}
    	}
    	SessionID = 0;
    }
	public static void Client(String Server_Name,int port) throws Exception
	{	
	    String Ciphers = "3DES/CFB for encryption,3DES/CBC for integrity protection,3DES/PCBC for encryption and integrity protection,Implement RC4 for encryption";
	    Random rand = new Random(); 
		int Ralice = rand.nextInt(10000) + 1; 
		Scanner user_input = new Scanner( System.in );
		int Choice = 0;
		while (Choice != 3)
		{
			
			System.out.println("Menu : \n1) File Transfer  \n2) File Transfer with Man In The Middle \n3) Exit\n");
			System.out.println("Enter Your Choice :");
			int i  = user_input.nextInt();
			Choice = i;
			switch(Choice)
			{
			case 1:
				if(SessionID==0)
					Client_Initial(Server_Name,port,Ciphers,Ralice);
				else
					Client_Resume(Server_Name,port,Ciphers,Ralice);
				Choice = 0;
				break;
			case 2:
				MIM=1;
				if(SessionID==0)
					Client_Initial(Server_Name,port,Ciphers,Ralice);
				else
					Client_Resume(Server_Name,port,Ciphers,Ralice);
				Choice = 0;
				MIM=0;
				break; 
			case 3:
				break;
			default : 
				System.out.println("Wrong Entry");
			}
			Thread.sleep(1000);
			System.out.println("\n\n");	
		}
	}
/* End of Client Server */
	

/* Main() - containing Main Menu */
	public static void main(String[] args) throws Exception 
	{
		Scanner user_input = new Scanner( System.in );
		int Choice =0;
		while (Choice != 3)
		{
			System.out.println("Menu : \n1) Start Client \n2) Start Server \n3) Exit\n");
			System.out.println("Enter Your Choice :");
			Choice  = user_input.nextInt();
			switch(Choice)
			{
			case 1:
				System.out.println("Enter Server's IP Address :");
				String Server_Name ;
				int port;
				Server_Name = user_input.next();
				System.out.println("Enter Port Number : ");
				port = user_input.nextInt();
				System.out.println("Enter the IV of length = 8 : ");
			    String IVI = user_input.nextLine();
			    while(IVI.length()!=8)
			      {
			    	  //System.out.println("Input length = "+ IVI.length());
			    	  System.out.println("Enter the IV of correct length i.e. 8 :");
			          IVI = user_input.nextLine();
			      }
			    IV = IVI.getBytes();
			    Client(Server_Name, port);
				Choice = 3;
				break;
			case 2:
				System.out.println("Enter Port Number : ");
				port = user_input.nextInt();
				System.out.println("Enter the IV : (length = 8 only)");
				String IVI1 = user_input.nextLine();
			    while(IVI1.length()!=8)
			      {
			    	  //System.out.println("Input length = "+ IVI1.length());
			    	  System.out.println("Enter the IV of correct length i.e. 8 :");
			          IVI1 = user_input.nextLine();
			      }
			    IV = IVI1.getBytes();
                Server(port);
				Choice = 3;
				break; 
			case 3:
				break; 
			default : 
				System.out.println("Wrong Entry");
			}
		}
	}
/*End of Main */
}
/* End of Program */
