package at.f0rki.kdftest;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import android.util.Log;

public class MyKDF {
	
	private static final String TAG = "MyKDF";

	public static final String DEFAULT_ALGORITHM = "md5";
	private MessageDigest md;
	private byte[] state;
	private byte[] salt;
	private int iterations;

	public MyKDF(byte[] salt, int iterations) throws NoSuchAlgorithmException {
		this(salt, iterations, DEFAULT_ALGORITHM);
	}

	public MyKDF(byte[] salt, int iterations, String hashalgorithm)
			throws NoSuchAlgorithmException {
		this.iterations = iterations;
		this.md = MessageDigest.getInstance(hashalgorithm);
		this.salt = salt;
		this.state = new byte[this.md.getDigestLength()];
	}

	public MyKDF(int saltsize, int iterations) throws NoSuchAlgorithmException {
		this(saltsize, iterations, DEFAULT_ALGORITHM);
	}

	public MyKDF(int saltsize, int iterations, String hashalgorithm)
			throws NoSuchAlgorithmException {
		this(null, iterations, hashalgorithm);
		this.salt = new byte[saltsize];
		SecureRandom rnd = new SecureRandom();
		rnd.nextBytes(this.salt);
	}

	public byte[] getSalt() {
		return salt;
	}

	public byte[] derive(byte[] input) {
		Log.d(TAG, "Deriving key from input using " + md.getClass().getCanonicalName());
		md.update(input);
		md.update(salt);
		this.state = md.digest();
		md.reset();
		for (int i = 0; i < this.iterations; ++i) {
			md.update(this.state);
			md.update(this.salt);
			this.state = md.digest();
			md.reset();
		}
		return this.state;
	}

	public byte[] derive(String input) {
		return derive(input.getBytes());
	}

	public String deriveHex(String input) {
		return PasswordInput.b16encode(derive(input));
	}
}
