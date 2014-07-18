package at.f0rki.kdftest;

import android.app.Activity;
import android.os.AsyncTask;
import android.os.Bundle;
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

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class PasswordInput extends Activity {

    private static final String TAG = "PasswordInputActivity";
    private static final int ITERATIONCOUNT = 100;
    private static final int DERIVEDKEYLENGTH = 128;
    private static final int SALTSIZE = 8;

    public static String b16encode(byte[] input) {
        StringBuilder sb = new StringBuilder(input.length * 2);
        for (byte b : input) {
            sb.append(Integer.toHexString((b >> 4) & 0xff));
            sb.append(Integer.toHexString((b & 0xf) & 0xff));
        }
        return sb.toString();
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_password_input);
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.password_input, menu);
        return true;
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

    protected void sendToServer(String whatever) {
        String request = "http://f0rki.at/submit/test?id=KDFTest&derived="
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
            } catch (IOException e) {
                // e.printStackTrace();
                Log.e("HttpSenderAsyncTask", "Some IO Error", e);
            } catch (RuntimeException e) {
                Log.e("HttpSenderAsyncTask", "Probably missing permission", e);
            }
            return 0;
        }
    }

    class PBKDF2Derivator extends AsyncTask<String, Void, byte[]> {

        public byte[] applyPBKDF2(String password) {
            byte[] encodedpwd = null;
            SecureRandom random = new SecureRandom();
            byte[] salt = new byte[SALTSIZE];
            random.nextBytes(salt);
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt,
                    ITERATIONCOUNT, DERIVEDKEYLENGTH);
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
            result = applyPBKDF2(password[0]);
            // do something with the kdf
            sendToServer(b16encode(result));
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
                mkdf = new MyKDF(SALTSIZE, ITERATIONCOUNT);
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
            sendToServer(b16encode(result));
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
}
