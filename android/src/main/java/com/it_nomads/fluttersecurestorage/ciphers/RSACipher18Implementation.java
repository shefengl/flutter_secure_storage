package com.it_nomads.fluttersecurestorage.ciphers;

import android.content.Context;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.security.keystore.StrongBoxUnavailableException;
import android.util.Log;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Calendar;
import java.util.Locale;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.security.auth.x500.X500Principal;

class RSACipher18Implementation {

    private final String KEY_ALIAS;
    private static final String KEYSTORE_PROVIDER_ANDROID = "AndroidKeyStore";
    private static final String TYPE_RSA = "RSA";
    private Context context;


    public RSACipher18Implementation(Context context) throws Exception {
        KEY_ALIAS = context.getPackageName() + ".FlutterSecureStoragePluginKey";
        this.context = context;
        createRSAKeysIfNeeded(context);
    }

    public byte[] wrap(Key key) throws Exception {
        PublicKey publicKey = getPublicKey();
        Cipher cipher = getRSACipher();
        cipher.init(Cipher.WRAP_MODE, publicKey);

        return cipher.wrap(key);
    }

    public Key unwrap(byte[] wrappedKey, String algorithm) throws Exception {
        PrivateKey privateKey = getPrivateKey();
        Cipher cipher = getRSACipher();
        cipher.init(Cipher.UNWRAP_MODE, privateKey);

        return cipher.unwrap(wrappedKey, algorithm, Cipher.SECRET_KEY);
    }

    public byte[] encrypt(byte[] input) throws Exception {
        PublicKey publicKey = getPublicKey();
        Cipher cipher = getRSACipher();
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        return cipher.doFinal(input);
    }

    public byte[] decrypt(byte[] input) throws Exception {
        PrivateKey privateKey = getPrivateKey();
        Cipher cipher = getRSACipher();
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        return cipher.doFinal(input);
    }

    public PrivateKey getPrivateKey() throws Exception {
        KeyStore ks = KeyStore.getInstance(KEYSTORE_PROVIDER_ANDROID);
        ks.load(null);

        Key key = ks.getKey(KEY_ALIAS, null);
        if (key == null) {
            throw new Exception("No key found under alias: " + KEY_ALIAS);
        }

        if (!(key instanceof PrivateKey)) {
            throw new Exception("Not an instance of a PrivateKey");
        }

        return (PrivateKey) key;
    }

    public Key getKey() throws Exception {
        KeyStore ks = KeyStore.getInstance(KEYSTORE_PROVIDER_ANDROID);
        ks.load(null);

        Key key = ks.getKey(KEY_ALIAS, null);
        if (key == null) {
            throw new Exception("No key found under alias: " + KEY_ALIAS);
        }

        return key;
    }

    public void deleteKey() throws Exception {
        KeyStore ks = KeyStore.getInstance(KEYSTORE_PROVIDER_ANDROID);
        ks.load(null);

        ks.deleteEntry(KEY_ALIAS);
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.N) {
            CompletableFuture<Long> task = CompletableFuture.supplyAsync(new Supplier<Long>() {
                @Override
                public Long get() {
                    try {
                        createRSAKeysIfNeeded(context);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                    return null;
                }
            });
        } else {
            new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        createRSAKeysIfNeeded(context);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }).start();
        }
    }



    public PublicKey getPublicKey() throws Exception {
        KeyStore ks = KeyStore.getInstance(KEYSTORE_PROVIDER_ANDROID);
        ks.load(null);

        Certificate cert = ks.getCertificate(KEY_ALIAS);
        if (cert == null) {
            throw new Exception("No certificate found under alias: " + KEY_ALIAS);
        }

        PublicKey key = cert.getPublicKey();
        if (key == null) {
            throw new Exception("No key found under alias: " + KEY_ALIAS);
        }

        return key;
    }

    public Cipher getRSACipher() throws Exception {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            return Cipher.getInstance("RSA/ECB/PKCS1Padding", "AndroidOpenSSL"); // error in android 6: InvalidKeyException: Need RSA private or public key
        } else {
            return Cipher.getInstance("RSA/ECB/PKCS1Padding", "AndroidKeyStoreBCWorkaround"); // error in android 5: NoSuchProviderException: Provider not available: AndroidKeyStoreBCWorkaround
        }
    }

    private void createRSAKeysIfNeeded(final Context context) throws Exception {
        KeyStore ks = KeyStore.getInstance(KEYSTORE_PROVIDER_ANDROID);
        ks.load(null);

        Key privateKey = ks.getKey(KEY_ALIAS, null);
        if (privateKey == null) {
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.N) {
                CompletableFuture<Long> task = CompletableFuture.supplyAsync(new Supplier<Long>() {
                    @Override
                    public Long get() {
                        try {
                            createKeys(context);
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                        return null;
                    }
                });
            } else {
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            createKeys(context);
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                }).start();
            }
        }
    }

    /**
     * Sets default locale.
     */
    private void setLocale(Locale locale) {
        Locale.setDefault(locale);
        Resources resources = context.getResources();
        Configuration config = resources.getConfiguration();
        config.locale = locale;
        resources.updateConfiguration(config, resources.getDisplayMetrics());
    }

    private void createKeys(Context context) throws Exception {
        Log.i("fluttersecurestorage", "Creating keys!");
        final Locale localeBeforeFakingEnglishLocale = Locale.getDefault();
        Locale initialLocale = Locale.getDefault();
        setLocale(Locale.ENGLISH);
        Calendar start = Calendar.getInstance();
        Calendar end = Calendar.getInstance();
        end.add(Calendar.YEAR, 25);

        KeyPairGenerator kpGenerator = KeyPairGenerator.getInstance(TYPE_RSA, KEYSTORE_PROVIDER_ANDROID);

        AlgorithmParameterSpec spec;

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            spec = new android.security.KeyPairGeneratorSpec.Builder(context)
                    .setAlias(KEY_ALIAS)
                    .setSubject(new X500Principal("CN=" + KEY_ALIAS))
                    .setSerialNumber(BigInteger.valueOf(1))
                    .setStartDate(start.getTime())
                    .setEndDate(end.getTime())
                    .build();
        } else {
            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_DECRYPT | KeyProperties.PURPOSE_ENCRYPT)
                    .setCertificateSubject(new X500Principal("CN=" + KEY_ALIAS))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                    .setCertificateSerialNumber(BigInteger.valueOf(1))
                    .setCertificateNotBefore(start.getTime())
                    .setCertificateNotAfter(end.getTime())
                    .setUserAuthenticationRequired(true);

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                builder.setIsStrongBoxBacked(true);
            }

            spec = builder.build();
        }
        try {
            Log.i("fluttersecurestorage", "Initializing");
            kpGenerator.initialize(spec);
            Log.i("fluttersecurestorage", "Generating key pair");
            kpGenerator.generateKeyPair();
        } catch (StrongBoxUnavailableException | InvalidAlgorithmParameterException se) {
            spec = new KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_DECRYPT | KeyProperties.PURPOSE_ENCRYPT)
                    .setCertificateSubject(new X500Principal("CN=" + KEY_ALIAS))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                    .setCertificateSerialNumber(BigInteger.valueOf(1))
                    .setCertificateNotBefore(start.getTime())
                    .setCertificateNotAfter(end.getTime())
                    .setUserAuthenticationRequired(true)
                    .build();
            kpGenerator.initialize(spec);
            kpGenerator.generateKeyPair();
        }
        setLocale(localeBeforeFakingEnglishLocale);
    }

    private void createKeyAes(Context context) {
        KeyGenParameterSpec.Builder paramsBuilder = new KeyGenParameterSpec.Builder(KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(true);


        KeyGenParameterSpec keyGenParams = paramsBuilder.build();
        KeyGenerator keyGenerator = null;
        try {
            keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,
                    KEYSTORE_PROVIDER_ANDROID);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
        }
        try {
            keyGenerator.init(keyGenParams);
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        keyGenerator.generateKey();
    }
}