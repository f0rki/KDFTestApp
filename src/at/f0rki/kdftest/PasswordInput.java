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
import android.view.Menu;
import android.view.View;
import android.widget.EditText;
import android.widget.Toast;

public class PasswordInput extends Activity {

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
			} catch (RuntimeException e) {
				Toast toast = Toast.makeText(getApplicationContext(),
						"Network Error", Toast.LENGTH_SHORT);
				toast.show();
			}

			long ret = 1;
			return ret;
		}
	}

	private static final int ITERATIONCOUNT = 100;
	private static final int DERIVEDKEYLENGTH = 128 / 8;
	private static final int SALTSIZE = 8;

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
		try {
			encodedpwd = f.generateSecret(spec).getEncoded();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		Toast toast = Toast.makeText(getApplicationContext(),
				"Applied PBKDF2!", Toast.LENGTH_SHORT);
		toast.show();

		// do something with the kdf
		sendToServer(b16encode(encodedpwd));
	}

	public void applyMyKDF(View view) {
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
			return;
		}
		byte[] encodedpwd = mkdf.derive(password);

		Toast toast = Toast.makeText(getApplicationContext(),
				"Applied custom KDF!", Toast.LENGTH_SHORT);
		toast.show();

		// do something with the kdf
		sendToServer(b16encode(encodedpwd));
	}

	protected String b16encode(byte[] input) {
		StringBuilder sb = new StringBuilder(input.length * 2);
		for (byte b : input) {
			sb.append(b >> 4);
			sb.append((b & 0xf0) >> 4);
		}
		return sb.toString();
	}

	protected void sendToServer(String whatever) {
		String request = "http://f0rki.at/submit/test?id=KDFTest&derived="
				+ whatever;
		new HttpSender().execute(request);
	}
}
