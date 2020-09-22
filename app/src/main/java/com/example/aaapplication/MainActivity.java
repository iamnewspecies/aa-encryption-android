package com.example.aaapplication;

import android.os.Build;
import android.os.Bundle;

import com.android.volley.Request;
import com.android.volley.RequestQueue;
import com.android.volley.Response;
import com.android.volley.VolleyError;
import com.android.volley.toolbox.JsonObjectRequest;
import com.android.volley.toolbox.JsonRequest;
import com.android.volley.toolbox.StringRequest;
import com.android.volley.toolbox.Volley;
import com.google.android.material.floatingactionbutton.FloatingActionButton;
import com.google.android.material.snackbar.Snackbar;

import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.JsonReader;
import android.util.Log;
import android.view.View;

import android.view.Menu;
import android.view.MenuItem;
import android.widget.Button;

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.UUID;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class MainActivity extends AppCompatActivity {
    // this is CR's public key. If you a generate a new Key there then you have to change it here too.
    String publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqepUVenHX0xDwJ9d8HalThvZccSBAs2lEaWVVODT+3ctPbVErEJRrHqKx7dfOOcj/CfS2taVWKMM9PtFvHKDXZbbEAH0ozdRg8LuhL3zagev185A/gppXkoOBO3sMpUivSwuijmlwaTMsiqhthcAOap0mACMKiXK4N9VJf61AuDqnjERzzaNso98sV+BseyzONcP7uAy66TjaN/VtonF8otWHUi5YacT7R8LuoRZro0iZ17aM3pDST5OJ1x4c+PSEZDQ7L0AHJpabit/Ze8PpNZE7LnYnwRqJbXSQYwuninAJRAw+1LTqY5e3/hWxDU2GmbGVRSsa6+i+bCk0lurzwIDAQAB";
    //only https urls are allowed
    // change this url according to your needs.
    String baseURL = "https://aa2909fd6e62.ngrok.io/api/v1/accounts";
    public static final int GCM_IV_LENGTH = 12;
    public static final int GCM_TAG_LENGTH = 16;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Button fab = findViewById(R.id.fab);
        fab.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                try {
                    dicoverAccounts();
                } catch (JSONException e) {
                    e.printStackTrace();
                }
            }
        });
    }

    private void dicoverAccounts() throws JSONException {
        final String nonce = UUID.randomUUID().toString();
        JSONObject request = new JSONObject();
        request.accumulate("phoneNumber" ,"9999999999");
        request.accumulate("fipId" ,"BANK123");
        request.accumulate("nonce" ,nonce);
        RequestQueue queue = Volley.newRequestQueue(this);
        String url = baseURL+ "/info";


        JsonObjectRequest stringRequest = new JsonObjectRequest(Request.Method.POST, url, request,
                new Response.Listener<JSONObject>() {
                    @Override
                    public void onResponse(JSONObject response) {
                        Log.d("DiscoverAccounts", response.toString());
                        try {
                            if(verifySignature(response)) {
                                String payload = new String(org.jose4j.base64url.Base64.decode(response.getString("payload")));
                                JSONObject jsonPayload = new JSONObject(payload);
                                if(nonce.equals(jsonPayload.getString("nonce"))) {

                                    //Sample 2FA Payload
                                    JSONObject secondFactor = new JSONObject();
                                    secondFactor.accumulate("last6Digit", "123456");
                                    secondFactor.accumulate("expiry", "05/27");
                                    secondFactor.accumulate("accountRefNumber", "5099176d-10d4-48e6-b249-92783cc394f8");
                                    secondFactor.accumulate("txnId", "4099176d-10d4-48e6-b249-92783cc394g9");


                                    SecretKey symmetricKey = generateAESKey();

                                    byte[] IV = new byte[GCM_IV_LENGTH];
                                    SecureRandom random = new SecureRandom();
                                    random.nextBytes(IV);

                                    String encryptedPayload = encryptPayload(secondFactor, symmetricKey, IV);

                                    String encryptedKey = encryptKey(symmetricKey, IV, jsonPayload.getString("publicKey"));
                                    JSONObject linkAccountRequest = new JSONObject();
                                    linkAccountRequest.accumulate("encryptedPayload", encryptedPayload);
                                    linkAccountRequest.accumulate("encryptedKey", encryptedKey);

                                    Log.d("linkAccountRequest", linkAccountRequest.toString(4));

                                    linkAccount(linkAccountRequest);
                                } else {
                                    Log.d("nonce", "Not matching");
                                }
                            } else {
                              // show error that it is
                                Log.d("JWS", "Verification failure");
                            }
                        } catch (JSONException e) {
                            e.printStackTrace();
                        }
                    }
                }, new Response.ErrorListener() {
                    @Override
                    public void onErrorResponse(VolleyError error) {
                        error.printStackTrace();
//                        Log.d("Discover accounts error", error.getMessage());
                    }
        });

// Add the request to the RequestQueue.
        queue.add(stringRequest);
    }
    private Boolean verifySignature(JSONObject response) {

        boolean isVerified = false;
        try {
            String compactSerialization = null;
            compactSerialization = response.getString("protected") + "." +
                    response.getString("payload") + "." +
                    response.getString("signature");
            JsonWebSignature jws = new JsonWebSignature();

            jws.setAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT,  AlgorithmIdentifiers.RSA_USING_SHA256));

            jws.setCompactSerialization(compactSerialization);

            byte[] buffer = Base64.decode(publicKey,  Base64.NO_WRAP);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(buffer);
            jws.setKey(keyFactory.generatePublic(keySpec));

            isVerified = jws.verifySignature();
            // Check the signature
        } catch (JSONException | JoseException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }

        return isVerified;
    }

    private String encryptKey(SecretKey symmetricKey, byte[] iv, String publicKey) {
        String encryptedKey = null;
        try {
            byte[] publicBytes = org.jose4j.base64url.Base64.decode(publicKey);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey pk = keyFactory.generatePublic(keySpec);


            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, pk);
            byte[] byteSymKey = symmetricKey.getEncoded();
            if(byteSymKey == null) {
                Log.d("nullSymmetricKey", "it is null");
            }

            byte[] key = new byte[iv.length + byteSymKey.length];
            System.arraycopy(iv, 0, key, 0, iv.length);
            System.arraycopy(byteSymKey, 0, key, iv.length, byteSymKey.length);

            byte[] ekb = cipher.doFinal(key);
            encryptedKey = Base64.encodeToString(ekb, Base64.NO_WRAP );
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }

        return encryptedKey;
    }

    private String encryptPayload(JSONObject payload, SecretKey key, byte[] IV) {
        String encryptedPayload = null;
        Cipher cipher = null;
        try {

            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.KITKAT) {


                cipher = Cipher.getInstance("AES/GCM/NoPadding");
                GCMParameterSpec gcmParameterSpec = null;
                gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, IV);

                cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
                byte[] ciphertext = cipher.doFinal(payload.toString().getBytes(Charset.defaultCharset()));

                encryptedPayload = new String(Base64.encode(ciphertext, Base64.NO_WRAP));
//                iv = new String(Base64.encode(cipher.getIV(), Base64.NO_WRAP));
            }

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }

        return encryptedPayload;
    }

    private void linkAccount(JSONObject linkAccountRequest) {
        RequestQueue queue = Volley.newRequestQueue(this);
        String url = baseURL + "/link";

        JsonObjectRequest jsonObjectRequest = new JsonObjectRequest(Request.Method.POST, url, linkAccountRequest,
                new Response.Listener<JSONObject>() {
                    @Override
                    public void onResponse(JSONObject response) {
                        Log.d("response", response.toString());
                    }
                }, new Response.ErrorListener() {
                    @Override
                    public void onErrorResponse(VolleyError error) {
                        error.printStackTrace();
                        Log.d("Discover accounts error", "" +error);
                    }
        });

// Add the request to the RequestQueue.
        queue.add(jsonObjectRequest);
    }

    private SecretKey generateAESKey() {
        SecretKey key = null;
        try {
            KeyGenerator keygen = KeyGenerator.getInstance("AES");
            keygen.init(256, new SecureRandom());
            key = keygen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return key;
    }
}