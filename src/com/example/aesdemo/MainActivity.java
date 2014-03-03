package com.example.aesdemo;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import com.example.aesdemo.CryptoUtil.CipherText;

import android.os.Bundle;
import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;
import android.util.Log;
import android.view.Menu;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.TextView;

public class MainActivity extends Activity {

	private final String TAG = "ENC";
	private static String PLAINTEXT = "This is a test sentence.";
	private static String PASSWD = "gogogo";
	private Button btn0, btn1, btn2;
	private TextView tv0, tv1, tv2;
	//private byte[] secretKey;
	private String decrypted;
	private List encrypted;
	private String aesKey, rsaPubKey, encryptedKey;
		 
    @Override
    protected void onCreate(Bundle savedInstanceState) {
      super.onCreate(savedInstanceState);
      setContentView(R.layout.activity_main);
        
      btn0 = (Button) findViewById(R.id.button0);
      btn1 = (Button) findViewById(R.id.button1);
      btn2 = (Button) findViewById(R.id.button2);
      tv0 = (TextView) findViewById(R.id.textView0);
      tv1 = (TextView) findViewById(R.id.textView1);
      tv2 = (TextView) findViewById(R.id.textView2);
      
      encrypted = null;
      decrypted = "";
      aesKey = "";
      rsaPubKey = "";
      encryptedKey = "";
                  
      btn0.setOnClickListener(new OnClickListener(){

  			@Override
  			public void onClick(View v) {
  				// TODO Auto-generated method stub
  			  aesKey =  PrepareAesKey(PASSWD);
  			  Log.d(TAG, "AES key: "+aesKey+" " +aesKey.length());
  			  rsaPubKey = PrepareRsaKeyPair();
  			  encryptedKey = RsaTextEncrypt(rsaPubKey, aesKey);
  			  Log.d(TAG, "Enc key: "+encryptedKey+" " +encryptedKey.length());
  			  tv0.setText("Keys ready.");
  			}
        	
      });
      
      btn1.setOnClickListener(new OnClickListener(){

        @Override
        public void onClick(View v) {
          // TODO Auto-generated method stub
          String decryptedAesKey = RsaTextDecrypt(encryptedKey);
          Log.d(TAG, "DEC AES key: "+decryptedAesKey+" " +decryptedAesKey.length());
          encrypted = AesTextEncrypt(decryptedAesKey, PLAINTEXT);
          tv1.setText((String)encrypted.get(0));
        }
          
      });
      
      btn2.setOnClickListener(new OnClickListener(){

        @Override
        public void onClick(View v) {
          // TODO Auto-generated method stub
          decrypted = AesTextDecrypt(RsaTextDecrypt(encryptedKey), encrypted);
          tv2.setText(decrypted);
        }
          
      });        
      
    }
    
    @Override
    public void onResume(){
      super.onResume();
    }
    
    @Override
    public void onPause(){
      super.onPause();
    }


    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
      // Inflate the menu; this adds items to the action bar if it is present.
      getMenuInflater().inflate(R.menu.main, menu);
      return true;
    }
    
    /**
     * Hashes given text using the algorithm specified in type.
     * Types include {md5, sha-1, sha-256, sha-384, sha-512}.
     * If type is empty, the default algorithm sha-256 is chosen.
     * 
     * @param text the text to be hashed
     * @param type the algorithm name in {md5, sha-1, sha-256, sha-384, sha-512}
     * @return hashed string
     */
    public String HashTextEncode(String text, String type) {
      String res = "";
      String alg = type;
      if(type == null) alg = "";
      try {
        res = CryptoUtil.hash(text.getBytes("UTF-8"), alg);
      } catch (NoSuchAlgorithmException e) {
        Log.d(TAG, "HashTextEncode:" + "NoSuchAlgorithmException. " + e.getMessage());
      } catch (UnsupportedEncodingException e) {
        Log.d(TAG, "HashTextEncode:" + "UnsupportedEncodingException. " + e.getMessage());
      }
      return res;
    }
    
    /**
     * Generates the HMAC (Hash-based Message Authentication Code)
     * of given text using the algorithm specified in type. 
     * Types include {hmacmd5, hmacsha1, hmacsha256, hmacsha384, hmacsha512}. 
     * If type is empty, the default algorithm hmacsha256 is chosen. 
     * Key is the secret phrase.
     * 
     * @param text the text to be encoded
     * @param key the secret phrase
     * @param type the algorithm name in {hmacmd5, hmacsha1, hmacsha256, hmacsha384, hmacsha512}
     * @return the HMAC string
     */
    public String HmacTextEncode(String text, String key, String type) {
      String res = "";
      String alg = type;
      if(type == null) alg = "";
      try {
        res = CryptoUtil.hmac(text.getBytes("UTF-8"), key.getBytes("UTF-8"), alg);
      } catch (InvalidKeyException e) {
        Log.d(TAG, "HmacTextEncode:" + "InvalidKeyException. " + e.getMessage());
      } catch (UnsupportedEncodingException e) {
        Log.d(TAG, "HmacTextEncode:" + "UnsupportedEncodingException. " + e.getMessage());
      } catch (NoSuchAlgorithmException e) {
        Log.d(TAG, "HmacTextEncode:" + "NoSuchAlgorithmException. " + e.getMessage());
      }
      return res;
    }
    
    /**
     * Generates new secret key for AES encryption and decryption. 
     * Password is the user’s password. Must be placed before new 
     * AES encryption and decryption. If this method is missing, 
     * the last secretKey in history will be used.
     * 
     * @param password
     * @return AES key in Base64 text
     */
    public String PrepareAesKey(String password) {
      String secret = "";
      try {
        byte[] salt = CryptoUtil.generateSalt();
        byte[] secretKey = CryptoUtil.getSecretKey(password.toCharArray(), salt);
        secret = Base64.encodeToString(secretKey, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
        Log.d(TAG, "Key prepared: " + CryptoUtil.toHexString(secretKey));
      } catch (NoSuchAlgorithmException e) {
        Log.d(TAG, "PrepareAesKey:" + "NoSuchAlgorithmException. " + e.getMessage());
      } catch (InvalidKeySpecException e) {
        Log.d(TAG, "PrepareAesKey:" + "InvalidKeySpecException. " + e.getMessage());
      } catch (NoSuchProviderException e) {
        Log.d(TAG, "PrepareAesKey:" + "NoSuchProviderException. " + e.getMessage());
      }
      return secret;
    }
    
    /**
     * Encrypts given text using AES-256 algorithm. 
     * 
     * @param key AES secret key as a base64 string
     * @param text the text to be encrypted
     * @return the 2-element List (ciphertext, hmac)
     */
    public List AesTextEncrypt(String key, String text) {      
      List<String> resList = new ArrayList<String>(2);
      resList.add("");
      resList.add("");
      byte[] secretKey = Base64.decode(key, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
      try {
        CipherText cipherText = CryptoUtil.aesEncrypt(secretKey, text.getBytes("UTF-8"));
        Log.d(TAG, "HMAC1: " + cipherText.hmac);
        resList.set(0, Base64.encodeToString(cipherText.text, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING));
        resList.set(1, cipherText.hmac);        
      } catch (UnsupportedEncodingException e) {
        Log.d(TAG, "AesTextEncrypt:" + "UnsupportedEncodingException. " + e.getMessage());
      } catch (InvalidKeyException e) {
        Log.d(TAG, "AesTextEncrypt:" + "InvalidKeyException. " + e.getMessage());
      } catch (NoSuchAlgorithmException e) {
        Log.d(TAG, "AesTextEncrypt:" + "NoSuchAlgorithmException. " + e.getMessage());
      } catch (NoSuchPaddingException e) {
        Log.d(TAG, "AesTextEncrypt:" + "NoSuchPaddingException. " + e.getMessage());
      } catch (InvalidAlgorithmParameterException e) {
        Log.d(TAG, "AesTextEncrypt:" + "InvalidAlgorithmParameterException. " + e.getMessage());
      } catch (IllegalBlockSizeException e) {
        Log.d(TAG, "AesTextEncrypt:" + "IllegalBlockSizeException. " + e.getMessage());
      } catch (BadPaddingException e) {
        Log.d(TAG, "AesTextEncrypt:" + "BadPaddingException. " + e.getMessage());
      }
      return resList;
    }
    
    /**
     * Decrypts given text using AES-256 algorithm.
     * 
     * @param key AES secret key as a base64 string
     * @param encrypted the 2-element List (ciphertext, hmac)
     * @return decrypted text
     */
    public String AesTextDecrypt(String key, List encrypted) {
      String res = "";
      CipherText cipherText;
      byte[] secretKey = Base64.decode(key, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
      try {
        cipherText = new CipherText(Base64.decode((String) encrypted.get(0), Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING), (String) encrypted.get(1));
        byte[] decrypted = CryptoUtil.aesDecrypt(secretKey, cipherText);
        res = new String(decrypted, "UTF-8");
      } catch (IllegalArgumentException e) {
        Log.d(TAG, "AesTextDecrypt:" + "IllegalArgumentException." + e.getMessage());
      } catch (UnsupportedEncodingException e) {
        Log.d(TAG, "AesTextDecrypt:" + "UnsupportedEncodingException. " + e.getMessage());
      } catch (InvalidKeyException e) {
        Log.d(TAG, "AesTextDecrypt:" + "InvalidKeyException. " + e.getMessage());
      } catch (NoSuchAlgorithmException e) {
        Log.d(TAG, "AesTextDecrypt:" + "NoSuchAlgorithmException. " + e.getMessage());
      } catch (NoSuchPaddingException e) {
        Log.d(TAG, "AesTextDecrypt:" + "NoSuchPaddingException. " + e.getMessage());
      } catch (InvalidAlgorithmParameterException e) {
        Log.d(TAG, "AesTextDecrypt:" + "InvalidAlgorithmParameterException. " + e.getMessage());
      } catch (IllegalBlockSizeException e) {
        Log.d(TAG, "AesTextDecrypt:" + "IllegalBlockSizeException. " + e.getMessage());
      } catch (BadPaddingException e) {
        Log.d(TAG, "AesTextDecrypt:" + "BadPaddingException. " + e.getMessage());
      }    
      return res;
    }
    
    /**
     * Generates RSA keypair. Must be placed before new 
     * RSA encryption and decryption. If this method is missing, 
     * the last keypair in history will be used.
     * 
     * @return the public key encoded in base64 text
     */
    public String PrepareRsaKeyPair(){
      String pubKeyString = "";
      try {
        byte[][] kp = CryptoUtil.generateRsaKeyPair();
        pubKeyString = Base64.encodeToString(kp[0], Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
        SharedPreferences sharedPreferences = this.getSharedPreferences("TinyDB1", Context.MODE_PRIVATE);
        SharedPreferences.Editor sharedPrefsEditor = sharedPreferences.edit();
        sharedPrefsEditor.putString("_RSA_PRI_KEY", Base64.encodeToString(kp[1], Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING));
        sharedPrefsEditor.commit();
      } catch (NoSuchAlgorithmException e) {
        Log.d(TAG, "PrepareRsaKeyPair:" + "NoSuchAlgorithmException. " + e.getMessage());
      } catch (InvalidKeySpecException e) {
        Log.d(TAG, "PrepareRsaKeyPair:" + "InvalidKeySpecException. " + e.getMessage());
      } catch (IOException e) {
        Log.d(TAG, "PrepareRsaKeyPair:" + "IOException. " + e.getMessage());
      }
      return pubKeyString;
    }
    
    /**
     * Encrypts text with RSA public key
     * 
     * @param key the RSA public key in Base64 string (UrlSafe & NoWrap)
     * @param text Base64 text to be encrypted
     * @return encrypted text in Base64
     */
    public String RsaTextEncrypt(String key, String text){
      String res = "";
      byte[] pubKey = Base64.decode(key, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
      try {
        byte[] encrypted = CryptoUtil.rsaEncrypt(pubKey, text.getBytes("UTF-8"));
        res = Base64.encodeToString(encrypted, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
      } catch (UnsupportedEncodingException e) {
        Log.d(TAG, "RsaTextEncrypt:" + "UnsupportedEncodingException. " + e.getMessage());
      } catch (InvalidKeyException e) {
        Log.d(TAG, "RsaTextEncrypt:" + "InvalidKeyException. " + e.getMessage());
      } catch (NoSuchAlgorithmException e) {
        Log.d(TAG, "RsaTextEncrypt:" + "NoSuchAlgorithmException. " + e.getMessage());
      } catch (NoSuchPaddingException e) {
        Log.d(TAG, "RsaTextEncrypt:" + "NoSuchPaddingException. " + e.getMessage());
      } catch (IllegalBlockSizeException e) {
        Log.d(TAG, "RsaTextEncrypt:" + "IllegalBlockSizeException. " + e.getMessage());
      } catch (BadPaddingException e) {
        Log.d(TAG, "RsaTextEncrypt:" + "BadPaddingException. " + e.getMessage());
      } catch (InvalidKeySpecException e) {
        Log.d(TAG, "RsaTextEncrypt:" + "InvalidKeySpecException. " + e.getMessage());
      }
      return res;
    }
    
    /**
     * Decrypts given ciphertext using RSA private key
     * 
     * @param text the ciphertext in Base64 to be decrypted
     * @return decrypted text
     */
    public String RsaTextDecrypt(String text){
      String res = "";
      byte[] encrypted = Base64.decode(text, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
      SharedPreferences sharedPreferences = this.getSharedPreferences("TinyDB1", Context.MODE_PRIVATE);
      byte[] priKey = Base64.decode(sharedPreferences.getString("_RSA_PRI_KEY", ""), Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
      try {        
        byte[] decrypted = CryptoUtil.rsaDecrypt(priKey, encrypted);
        res = new String(decrypted, "UTF-8");
      } catch (IllegalArgumentException e) {
        Log.d(TAG, "RsaTextDecrypt:" + "IllegalArgumentException." + e.getMessage());
      } catch (UnsupportedEncodingException e) {
        Log.d(TAG, "RsaTextDecrypt:" + "UnsupportedEncodingException. " + e.getMessage());
      } catch (InvalidKeyException e) {
        Log.d(TAG, "RsaTextDecrypt:" + "InvalidKeyException. " + e.getMessage());
      } catch (NoSuchAlgorithmException e) {
        Log.d(TAG, "RsaTextDecrypt:" + "NoSuchAlgorithmException. " + e.getMessage());
      } catch (NoSuchPaddingException e) {
        Log.d(TAG, "RsaTextDecrypt:" + "NoSuchPaddingException. " + e.getMessage());
      } catch (IllegalBlockSizeException e) {
        Log.d(TAG, "RsaTextDecrypt:" + "IllegalBlockSizeException. " + e.getMessage());
      } catch (BadPaddingException e) {
        Log.d(TAG, "RsaTextDecrypt:" + "BadPaddingException. " + e.getMessage());
      } catch (InvalidKeySpecException e) {
        Log.d(TAG, "RsaTextDecrypt:" + "InvalidKeySpecException. " + e.getMessage());
      }    
      return res;
    }
    
}
