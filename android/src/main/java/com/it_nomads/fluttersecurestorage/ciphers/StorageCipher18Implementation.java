package com.it_nomads.fluttersecurestorage.ciphers;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;
import android.util.Log;

import androidx.biometric.BiometricPrompt;

import com.it_nomads.fluttersecurestorage.AuthenticationHelper;

import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

@SuppressLint("ApplySharedPref")
public class StorageCipher18Implementation implements StorageCipher {

    private static final int ivSize = 16;
    private static final int keySize = 16;
    private static final String KEY_ALGORITHM = "AES";
    private static final String AES_PREFERENCES_KEY = "VGhpcyBpcyB0aGUga2V5IGZvciBhIHNlY3VyZSBzdG9yYWdlIEFFUyBLZXkK";
    private static final String SHARED_PREFERENCES_NAME = "FlutterSecureKeyStorage";

    private Key secretKey;
    private final Cipher cipher;
    private final SecureRandom secureRandom;
    private final RSACipher18Implementation mRsaCipher;

    public StorageCipher18Implementation(Context context) throws Exception {
        secureRandom = new SecureRandom();
        mRsaCipher = new RSACipher18Implementation(context);

        SharedPreferences preferences = context.getSharedPreferences(SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = preferences.edit();

        String aesKey = preferences.getString(AES_PREFERENCES_KEY, null);

//        cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");

        cipher = mRsaCipher.getRSACipher();
        if (aesKey != null) {
            byte[] encrypted;
            try {
                encrypted = Base64.decode(aesKey, Base64.DEFAULT);
                secretKey = mRsaCipher.getPublicKey();
                return;
            } catch (Exception e) {
                Log.e("StorageCipher18Impl", "unwrap key failed", e);
                encrypted = new byte[0];
            }
        }

        byte[] key = new byte[keySize];
        secureRandom.nextBytes(key);
//        secretKey = new SecretKeySpec(key, KEY_ALGORITHM);
        secretKey = mRsaCipher.getPublicKey();

//        byte[] encryptedKey = rsaCipher.wrap(secretKey);
        editor.putString(AES_PREFERENCES_KEY, Base64.encodeToString(secretKey.getEncoded(), Base64.DEFAULT));
        editor.commit();
    }

    @Override
    public byte[] encrypt(byte[] input, Activity activity, final AuthenticationHelper authenticationHelper) throws Exception {
        byte[] iv = new byte[ivSize];
        secureRandom.nextBytes(iv);

        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.ENCRYPT_MODE, mRsaCipher.getPublicKey());

//        activity.runOnUiThread(new Runnable() {
//            @Override
//            public void run() {
//                authenticationHelper.authenticate(new BiometricPrompt.CryptoObject(cipher));
//            }
//        });

//        byte[] payload = cipher.doFinal(input);
//        byte[] combined = new byte[iv.length + payload.length];
//
//        System.arraycopy(iv, 0, combined, 0, iv.length);
//        System.arraycopy(payload, 0, combined, iv.length, payload.length);

        return cipher.doFinal(input);
    }

    @Override
    public byte[] decrypt(byte[] input, Activity activity, final AuthenticationHelper authenticationHelper) throws Exception {
        byte[] iv = new byte[ivSize];
//        System.arraycopy(input, 0, iv, 0, iv.length);
//        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
//
//        int payloadSize = input.length - ivSize;
//        byte[] payload = new byte[payloadSize];
//        System.arraycopy(input, iv.length, payload, 0, payloadSize);

        cipher.init(Cipher.DECRYPT_MODE, mRsaCipher.getPrivateKey());
        Log.e("re", "read");

        activity.runOnUiThread(new Runnable() {
            @Override
            public void run() {
                authenticationHelper.authenticate(new BiometricPrompt.CryptoObject(cipher));
            }
        });

        return iv;
    }


    public static void moveSecretFromPreferencesIfNeeded(SharedPreferences oldPreferences, Context context) {
        String existedSecretKey = oldPreferences.getString(AES_PREFERENCES_KEY, null);
        if (existedSecretKey == null) {
            return;
        }

        SharedPreferences.Editor oldEditor = oldPreferences.edit();
        oldEditor.remove(AES_PREFERENCES_KEY);
        oldEditor.commit();

        SharedPreferences newPreferences = context.getSharedPreferences(SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE);
        SharedPreferences.Editor newEditor = newPreferences.edit();
        newEditor.putString(AES_PREFERENCES_KEY, existedSecretKey);
        newEditor.commit();
    }

}
