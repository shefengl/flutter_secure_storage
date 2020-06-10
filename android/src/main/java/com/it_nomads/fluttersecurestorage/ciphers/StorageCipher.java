package com.it_nomads.fluttersecurestorage.ciphers;

import android.app.Activity;

import com.it_nomads.fluttersecurestorage.AuthenticationHelper;

public interface StorageCipher {
  byte[] encrypt(byte[] input, Activity activity, AuthenticationHelper authenticationHelper) throws Exception;

  byte[] decrypt(byte[] input, Activity activity, AuthenticationHelper authenticationHelper) throws Exception;
}
