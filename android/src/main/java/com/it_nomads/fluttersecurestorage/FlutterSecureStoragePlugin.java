package com.it_nomads.fluttersecurestorage;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Handler;
import android.os.Looper;
import android.util.Base64;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.biometric.BiometricPrompt;
import androidx.fragment.app.FragmentActivity;
import androidx.lifecycle.Lifecycle;

import com.it_nomads.fluttersecurestorage.ciphers.StorageCipher;
import com.it_nomads.fluttersecurestorage.ciphers.StorageCipher18Implementation;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import io.flutter.embedding.engine.plugins.FlutterPlugin;
import io.flutter.embedding.engine.plugins.activity.ActivityAware;
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding;
import io.flutter.plugin.common.BinaryMessenger;
import io.flutter.plugin.common.MethodCall;
import io.flutter.plugin.common.MethodChannel;
import io.flutter.plugin.common.MethodChannel.MethodCallHandler;
import io.flutter.plugin.common.MethodChannel.Result;
import io.flutter.plugin.common.PluginRegistry.Registrar;

@SuppressLint("ApplySharedPref")
public class FlutterSecureStoragePlugin implements MethodCallHandler, FlutterPlugin, ActivityAware {

    private MethodChannel channel;
    private SharedPreferences preferences;
    private Charset charset;
    private StorageCipher storageCipher;
    private AuthenticationHelper authenticationHelper;
    private final AtomicBoolean authInProgress = new AtomicBoolean(false);

    private Activity activity;
    private Lifecycle lifecycle;
    private static final String ELEMENT_PREFERENCES_KEY_PREFIX = "VGhpcyBpcyB0aGUgcHJlZml4IGZvciBhIHNlY3VyZSBzdG9yYWdlCg";
    private static final String SHARED_PREFERENCES_NAME = "FlutterSecureStorage";
    private static Context applicationContext;  //Necessary for deferred initialization of storageCipher

    public static void registerWith(Registrar registrar) {
      FlutterSecureStoragePlugin instance = new FlutterSecureStoragePlugin(registrar.activity());
      instance.initInstance(registrar.messenger(), registrar.context());

    }

    private FlutterSecureStoragePlugin(Activity activity) {
        this.activity = activity;
    }

    public void initInstance(BinaryMessenger messenger, Context context) {
      try {
          applicationContext = context.getApplicationContext();
          preferences = context.getSharedPreferences(SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE);
          charset = StandardCharsets.UTF_8;
          StorageCipher18Implementation.moveSecretFromPreferencesIfNeeded(preferences, context);

          channel = new MethodChannel(messenger, "plugins.it_nomads.com/flutter_secure_storage");
          channel.setMethodCallHandler(this);
      } catch (Exception e) {
          Log.e("FlutterSecureStoragePl", "Registration failed", e);
      }
    }

    private void createBioCallback(final MethodCall methodCall, final Result result) {
        int failureCount = 0;
        authenticationHelper = new AuthenticationHelper(lifecycle, (FragmentActivity) activity,
                new AuthenticationHelper.AuthCompletionHandler() {
                    @Override
                    public void onSuccess(BiometricPrompt.CryptoObject cryptoObject) {
                        if (authInProgress.compareAndSet(true, false)) {
                            processSuccess(cryptoObject, methodCall, result);
                        }
                    }

                    @Override
                    public void onFailure(final BiometricPrompt biometricPrompt) {
                        if (authInProgress.compareAndSet(true, false)) {
                            result.success(null);
                            if (biometricPrompt != null) {
                                Handler timoutHandler = new Handler();
                                timoutHandler.postDelayed(new Runnable() {
                                    @Override
                                    public void run() {
                                        biometricPrompt.cancelAuthentication();
                                    }
                                }, 3000);

                            }
                        }
                    }

                    @Override
                    public void onError(String code, String error) {
                        if (authInProgress.compareAndSet(true, false)) {
                            result.error(code, error, null);
                        }
                    }
                });
    }

    private void processSuccess(BiometricPrompt.CryptoObject cryptoObject, MethodCall methodCall, Result methodResult) {


        try {
            if (methodCall.method.equals("write")) {
                byte[] payload;
                Map arguments = (Map) methodCall.arguments;
                String key = getKeyFromCall(methodCall);
                String value = (String) arguments.get("value");
                payload = cryptoObject.getCipher().doFinal(value.getBytes(charset));
                SharedPreferences.Editor editor = preferences.edit();

                editor.putString(key, Base64.encodeToString(payload, 0));
                editor.commit();
            } else if (methodCall.method.equals("read")) {
                Map arguments = (Map) methodCall.arguments;
                String key = getKeyFromCall(methodCall);
                String encoded = preferences.getString(key, null);
                byte[] data = Base64.decode(encoded, 0);
                byte[] result = cryptoObject.getCipher().doFinal(data);
                methodResult.success(new String(result, charset));
            }

        } catch (BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
    }

    /**
     * This must be run in a separate Thread from an async method to avoid hanging UI thread on
     * live devices in release mode.
     * The most convenient place for that appears to be onMethodCall().
     */
    private void ensureInitStorageCipher() {
        if(storageCipher == null) { //Check to avoid unnecessary entry into syncronized block
            synchronized (this) {
                if(storageCipher == null) { //Check inside sync block to avoid race condition.
                    try {
                        Log.d("FlutterSecureStoragePl", "Initializing StorageCipher");
                        storageCipher = new StorageCipher18Implementation(applicationContext);
                        Log.d("FlutterSecureStoragePl", "StorageCipher initialization complete");
                    } catch (Exception e) {
                        Log.e("FlutterSecureStoragePl", "StorageCipher initialization failed", e);
                    }
                }
            }
        }
    }

    @Override
    public void onAttachedToEngine(FlutterPluginBinding binding) {
      initInstance(binding.getBinaryMessenger(), binding.getApplicationContext());
    }

    @Override
    public void onDetachedFromEngine(FlutterPluginBinding binding) {
      channel.setMethodCallHandler(null);
      channel = null;
    }

    @Override
    public void onMethodCall(MethodCall call, Result rawResult) {
        MethodResultWrapper result = new MethodResultWrapper(rawResult);
        new Thread(new MethodRunner(call, result)).start();
    }

    private String getKeyFromCall(MethodCall call) {
        Map arguments = (Map) call.arguments;
        String rawKey = (String) arguments.get("key");
        String key = addPrefixToKey(rawKey);
        return key;
    }

    private Map<String, String> readAll() throws Exception {
        @SuppressWarnings("unchecked")
        Map<String, String> raw = (Map<String, String>) preferences.getAll();

        Map<String, String> all = new HashMap<>();
        for (Map.Entry<String, String> entry : raw.entrySet()) {
            String key = entry.getKey().replaceFirst(ELEMENT_PREFERENCES_KEY_PREFIX + '_', "");
            String rawValue = entry.getValue();
            String value = decodeRawValue(rawValue);

            all.put(key, value);
        }
        return all;
    }

    private void deleteAll() {
        SharedPreferences.Editor editor = preferences.edit();

        editor.clear();
        editor.commit();
    }

    private void write(final String key, final String value) throws Exception {
        byte[] result = storageCipher.encrypt(value.getBytes(charset), activity, authenticationHelper);
        SharedPreferences.Editor editor = preferences.edit();

        editor.putString(key, Base64.encodeToString(result, 0));
        editor.commit();
    }

    private String read(String key) throws Exception {
        String encoded = preferences.getString(key, null);
        if (encoded == null) {
            return null;
        }
        byte[] data = Base64.decode(encoded, 0);
        byte[] result = storageCipher.decrypt(data, activity, authenticationHelper);
        return encoded;
    }

    private void delete(String key) {
        SharedPreferences.Editor editor = preferences.edit();

        editor.remove(key);
        editor.commit();
    }

    private String addPrefixToKey(String key) {
        return ELEMENT_PREFERENCES_KEY_PREFIX + "_" + key;
    }

    private String decodeRawValue(String value) throws Exception {
        if (value == null) {
            return null;
        }
        byte[] data = Base64.decode(value, 0);
        byte[] result = storageCipher.decrypt(data, activity, authenticationHelper);

        return new String(result, charset);
    }

    /**
     * Wraps the functionality of onMethodCall() in a Runnable for execution in a new Thread.
     */
    class MethodRunner implements Runnable {
        private final MethodCall call;
        private final Result result;

        MethodRunner(MethodCall call, Result result) {
            this.call = call;
            this.result = result;
        }

        @Override
        public void run() {
            try {
                ensureInitStorageCipher();
                createBioCallback(call, result);
                switch (call.method) {
                    case "write": {
                        String key = getKeyFromCall(call);
                        Map arguments = (Map) call.arguments;

                        String value = (String) arguments.get("value");
                        write(key, value);
                        result.success(null);
                        break;
                    }
                    case "read": {
                        if (authInProgress.get()){
                            result.error("Exception encountered", call.method, null);
                            return;
                        }
                        authInProgress.set(true);
                        String key = getKeyFromCall(call);
                        String value = read(key);
                        break;
                    }
                    case "readAll": {
                        Map<String, String> value = readAll();
                        result.success(value);
                        break;
                    }
                    case "delete": {
                        String key = getKeyFromCall(call);

                        delete(key);
                        result.success(null);
                        break;
                    }
                    case "deleteAll": {
                        deleteAll();
                        result.success(null);
                        break;
                    }
                    default:
                        result.notImplemented();
                        break;
                }

            } catch (Exception e) {
                StringWriter stringWriter = new StringWriter();
                e.printStackTrace(new PrintWriter(stringWriter));
                result.error("Exception encountered", call.method, stringWriter.toString());
            }
        }
    }

    /**
     * MethodChannel.Result wrapper that responds on the platform thread.
     */
    static class MethodResultWrapper implements Result {

        private final Result methodResult;
        private final Handler handler = new Handler(Looper.getMainLooper());

        MethodResultWrapper(Result methodResult) {
            this.methodResult = methodResult;
        }

        @Override
        public void success(final Object result) {
            handler.post(new Runnable() {
                @Override
                public void run() {
                    methodResult.success(result);
                }
            });
        }

        @Override
        public void error(final String errorCode, final String errorMessage, final Object errorDetails) {
            handler.post(new Runnable() {
                @Override
                public void run() {
                    methodResult.error(errorCode, errorMessage, errorDetails);
                }
            });
        }

        @Override
        public void notImplemented() {
            handler.post(new Runnable() {
                @Override
                public void run() {
                    methodResult.notImplemented();
                }
            });
        }
    }

    @Override
    public void onAttachedToActivity(@NonNull ActivityPluginBinding binding) {
        activity = binding.getActivity();
        channel.setMethodCallHandler(this);

    }

    @Override
    public void onDetachedFromActivityForConfigChanges() {
        lifecycle = null;
        activity = null;
    }

    @Override
    public void onReattachedToActivityForConfigChanges(@NonNull ActivityPluginBinding binding) {
        activity = binding.getActivity();
    }

    @Override
    public void onDetachedFromActivity() {
        activity = null;
        lifecycle = null;
        channel.setMethodCallHandler(null);
    }
}
