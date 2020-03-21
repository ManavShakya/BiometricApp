package com.example.biometricapp

import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import android.view.View
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import kotlinx.android.synthetic.main.activity_main.*
import java.nio.charset.Charset
import java.security.KeyStore
import java.util.concurrent.Executor
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class Main2Activity : AppCompatActivity() {

    private lateinit var executor: Executor
    private lateinit var biometricManager: BiometricManager
    private lateinit var biometricPrompt: BiometricPrompt
    private lateinit var mainLayout: View
    private lateinit var textView: EditText
    private lateinit var promptInfo: BiometricPrompt.PromptInfo
    private var isAuthorised = false
    private var readyToEncrypt: Boolean = false
    private lateinit var keyName: String
    private lateinit var ciphertext:ByteArray
    private lateinit var initializationVector: ByteArray

    private val keySize: Int = 256
    private val keystore = "AndroidKeyStore"
    private val encryptionBlockMode = KeyProperties.BLOCK_MODE_GCM
    private val encryptionPadding = KeyProperties.ENCRYPTION_PADDING_NONE
    private val encryptionAlgo = KeyProperties.KEY_ALGORITHM_AES

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        mainLayout = findViewById(R.id.mainLayout)
        mainLayout.visibility = View.GONE
        executor = ContextCompat.getMainExecutor(this)
        biometricManager = BiometricManager.from(this)
        authoriseUserSession(biometricManager)
        performCrypto()

    }

    /**
     * function to check if the user’s device supports biometric features before you perform any authentication.
     */
    private fun authoriseUserSession(biometricManager: BiometricManager) {
        when (biometricManager.canAuthenticate()) {

            BiometricManager.BIOMETRIC_SUCCESS -> authenticateUser(executor)
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> authenticateUser(executor)
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> Toast
                .makeText(this, "Biometric features are currently unavailable", Toast.LENGTH_LONG).show()
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> Toast
                .makeText(this, "Please setup biometric credentials and try again", Toast.LENGTH_LONG).show()
        }
    }

    private fun authenticateUser(executor: Executor){

        biometricPrompt = BiometricPrompt(this, executor,
            object : BiometricPrompt.AuthenticationCallback() {

                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    Log.d("MainActivity", "Authentication was successful")
                    if(isAuthorised)
                        transformData(result.cryptoObject)
                    else{
                        mainLayout.visibility = View.VISIBLE
                        isAuthorised = true
                    }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    // if (errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON)
                    //  biometricPrompt.cancelAuthentication()
                    Toast.makeText(applicationContext, errString, Toast.LENGTH_LONG).show()
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    Toast.makeText(applicationContext, "Authentication failed", Toast.LENGTH_SHORT).show()
                }
            })

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Authentication Required")
            .setSubtitle("Log in using Biometric")
            .setDescription("Touch your fingerprint sensor to authenticate")
            .setDeviceCredentialAllowed(true)
            //.setNegativeButtonText("Use credentials")
            //.setConfirmationRequired(true)
            .build()

        biometricPrompt.authenticate(promptInfo)

    }

    private fun performCrypto() {
        // e.g. secretKeyName = "biometric_sample_encryption_key"
        keyName = "biometric_sample_encryption_key"
        textView = findViewById(R.id.input_view)
        encrypt_button.setOnClickListener  { authenticateToEncrypt() }
        decrypt_button.setOnClickListener { authenticateToDecrypt() }
    }

    private fun authenticateToEncrypt() {
        readyToEncrypt = true
        if (BiometricManager.from(applicationContext).canAuthenticate() == BiometricManager
                .BIOMETRIC_SUCCESS) {
            //This method fetches or generates an instance of SecretKey and then initializes the Cipher with the key for encryption.
            // The secret key uses [ENCRYPT_MODE][Cipher.ENCRYPT_MODE] is used.
            val cipher = getCipher()
            val secretKey = getOrCreateSecretKey(keyName)
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)
            biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
        }
    }

    private fun authenticateToDecrypt() {
        readyToEncrypt = false
        if (BiometricManager.from(applicationContext).canAuthenticate() == BiometricManager
                .BIOMETRIC_SUCCESS) {
            //This method fetches or generates an instance of SecretKey and then initializes the Cipher with the key for decryption.
            // The secret key uses [DECRYPT_MODE][Cipher.DECRYPT_MODE] is used.
            val cipher = getCipher()
            val secretKey = getOrCreateSecretKey(keyName)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, initializationVector))
            biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
        }
    }

    private fun transformData(cryptoObject: BiometricPrompt.CryptoObject?) {

        val data = if (readyToEncrypt) {
            val cipher = cryptoObject?.cipher
            val plainText = textView.text.toString()
            //The Cipher created for encryption and passed to biometric is used here
            val cipherText = cipher!!.doFinal(plainText.toByteArray(Charset.forName("UTF-8")))
            val encryptedData = EncryptedData(cipherText,cipher.iv)
            ciphertext = encryptedData.cipherText
            initializationVector = encryptedData.initializationVector
            String(ciphertext, Charset.forName("UTF-8"))
        } else {
            decryptData(ciphertext, cryptoObject?.cipher!!)
        }
        textView.setText(data)
    }

    class EncryptedData(val cipherText: ByteArray, val initializationVector: ByteArray)

    //The Cipher created with [getInitializedCipherForEncryption] is used here
    private fun encryptData(plaintext: String, cipher: Cipher): EncryptedData {
        val cipherText = cipher.doFinal(plaintext.toByteArray(Charset.forName("UTF-8")))
        return EncryptedData(cipherText,cipher.iv)
    }

    //The Cipher created with [getInitializedCipherForDecryption] is used here
    private fun decryptData(cipherText: ByteArray, cipher: Cipher): String {
        val plainText = cipher.doFinal(cipherText)
        return String(plainText, Charset.forName("UTF-8"))
    }

    private fun getCipher(): Cipher {
        val transformation = "$encryptionAlgo/$encryptionBlockMode/$encryptionPadding"
        return Cipher.getInstance(transformation)
    }

    private fun getOrCreateSecretKey(keyName: String): SecretKey {
        // If Secretkey was previously created for that keyName, then grab and return it.
        val keyStore = KeyStore.getInstance(keystore)
        keyStore.load(null) // Keystore must be loaded before it can be accessed
        keyStore.getKey(keyName, null)?.let { return it as SecretKey }

        // if you reach here, then a new SecretKey must be generated for that keyName
        val paramsBuilder = KeyGenParameterSpec
            .Builder(keyName, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
        paramsBuilder.apply {
            setBlockModes(encryptionBlockMode)
            setEncryptionPaddings(encryptionPadding)
            setKeySize(keySize)
            setUserAuthenticationRequired(true)
        }

        val keyGenParams = paramsBuilder.build()
        val keyGenerator = KeyGenerator.getInstance(encryptionAlgo, keystore)
        keyGenerator.init(keyGenParams)
        return keyGenerator.generateKey()
    }

}
