package at.f0rki.kdftest;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.DefaultHttpClient;

import android.app.Activity;
import android.os.AsyncTask;
import android.os.Bundle;
import android.util.Log;
import android.view.Menu;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

public class PasswordInput extends Activity {

	private static final String TAG = "PasswordInputActivity";

	class HttpSender extends AsyncTask<String, Void, Long> {
		protected Long doInBackground(String... urls) {
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

			long ret = 1;
			return ret;
		}
	}

	class Derivator extends AsyncTask<Integer, Void, byte[]> {

		public static final int DO_PBKDF2 = 1;
		public static final int DO_MYKDF = 2;

		private int kdftype;

		public byte[] applyPBKDF2() {
			kdftype = DO_PBKDF2;

			// get string from textview
			EditText pwbox = (EditText) findViewById(R.id.passwordBox);
			String password = pwbox.getText().toString();

			// apply the actual kdf
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

		public byte[] applyMyKDF() {
			kdftype = DO_MYKDF;

			// get string from textview
			EditText pwbox = (EditText) findViewById(R.id.passwordBox);
			String password = pwbox.getText().toString();

			// apply the actual kdf
			MyKDF mkdf = null;
			try {
				mkdf = new MyKDF(SALTSIZE, ITERATIONCOUNT);
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
				Toast toast = Toast.makeText(getApplicationContext(),
						"Failed to apply custom KDF!", Toast.LENGTH_LONG);
				toast.show();
				return null;
			}
			byte[] encodedpwd = mkdf.derive(password);
			return encodedpwd;
		}

		@Override
		protected byte[] doInBackground(Integer... cmd) {
			byte[] result = null;
			switch (cmd[0]) {
			case DO_PBKDF2:
				result = applyPBKDF2();
				break;
			case DO_MYKDF:
				result = applyMyKDF();
				break;
			default:
				break;
			}
			// do something with the kdf
			sendToServer(b16encode(result));
			return result;
		}

		protected void onPostExecute(byte[] result) {
			switch (kdftype) {
			case DO_PBKDF2:
				showDialog("Successfully applied PBKDF2");
				break;
			case DO_MYKDF:
				showDialog("Successfully applied MYKDF");
				break;
			default:
				break;
			}
			TextView derived = (TextView) findViewById(R.id.derivedValue);
			String b16 = b16encode(result);
			derived.setText(b16);
		}
	}

	private static final int ITERATIONCOUNT = 100;
	private static final int DERIVEDKEYLENGTH = 128;
	private static final int SALTSIZE = 8;

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_password_input);
	}

	public void showDialog(String string) {
		// TODO Auto-generated method stub

	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.password_input, menu);
		return true;
	}

	public void applyPBKDF2(View view) {
		new Derivator().execute(Derivator.DO_PBKDF2);
	}

	public void applyMyKDF(View view) {
		new Derivator().execute(Derivator.DO_MYKDF);
	}

	public static String b16encode(byte[] input) {
		StringBuilder sb = new StringBuilder(input.length * 2);
        for (byte b : input) {
            sb.append(Integer.toHexString((b >> 4) & 0xff));
            sb.append(Integer.toHexString((b & 0xf) & 0xff));
        }
        return sb.toString();

	}

	protected void sendToServer(String whatever) {
		String request = "http://f0rki.at/submit/test?id=KDFTest&derived="
				+ whatever;
		new HttpSender().execute(request);
	}
}
