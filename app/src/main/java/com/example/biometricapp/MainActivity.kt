package com.example.biometricapp

import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import android.view.View
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

class MainActivity : AppCompatActivity() {

    private lateinit var executor: Executor
    private lateinit var biometricManager: BiometricManager
    private lateinit var biometricPrompt: BiometricPrompt
    private lateinit var promptInfo : BiometricPrompt.PromptInfo
    private var isAuthorised = false    // a flag for differentiating the authentication use case
    private var isEncrypt: Boolean = false
    private lateinit var keyName: String
    private lateinit var ciphertext:ByteArray
    private lateinit var initializationVector: ByteArray

    private val keySize: Int = 256
    private val keystore = "AndroidKeyStore"
    private val encryptionBlockMode = KeyProperties.BLOCK_MODE_GCM
    private val encryptionPadding = KeyProperties.ENCRYPTION_PADDING_PKCS7
    private val encryptionAlgo = KeyProperties.KEY_ALGORITHM_HMAC_SHA256

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        mainLayout.visibility = View.GONE
        executor = ContextCompat.getMainExecutor(this)
        biometricManager = BiometricManager.from(this)
        //
        authoriseUserSession(biometricManager)
        performCrypto()

    }

    /**
     * function to check if the user’s device supports biometric features before you perform any authentication.
     */
    private fun authoriseUserSession(biometricManager: BiometricManager) {
        when (biometricManager.canAuthenticate()) {

            BiometricManager.BIOMETRIC_SUCCESS -> authenticateUser(executor)
            // for devices which don't have fingerprint sensor, they can use credentials for authentication
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> authenticateUser(executor)
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> Toast
                .makeText(this, "Biometric features are currently unavailable", Toast.LENGTH_LONG).show()
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> Toast
                .makeText(this, "Please setup biometric credentials and try again", Toast.LENGTH_LONG).show()
        }
    }

    private fun authenticateUser(executor: Executor){

        // promptinfo and biometric prompt are initialised here and will be shown in both use cases
        biometricPrompt = createBiometricPrompt()
        promptInfo = createPromptInfo()
        biometricPrompt.authenticate(promptInfo)

    }

    private fun createBiometricPrompt(): BiometricPrompt {
        return BiometricPrompt(this, executor,
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
                    Toast.makeText(applicationContext, errString, Toast.LENGTH_LONG).show()
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    Toast.makeText(applicationContext, "Authentication failed", Toast.LENGTH_SHORT).show()
                }
            })
    }

    private fun performCrypto() {
        // secretkey
        keyName = "biometric_sample_encryption_key"
        buttonEncrypt.setOnClickListener  { authenticateToEncrypt() }
        buttonDecrypt.setOnClickListener { authenticateToDecrypt() }
    }

    private fun authenticateToEncrypt() {
        isEncrypt = true
        if (BiometricManager.from(applicationContext).canAuthenticate() == BiometricManager
                .BIOMETRIC_SUCCESS) {
            // Fetches/creates an instance of SecretKey using [Cipher.ENCRYPT_MODE] and
            // then initializes the Cipher with that key for encryption.
            val cipher = getCipher()
            val secretKey = getSecretKey(keyName)
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)
            biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
        }
    }

    private fun createPromptInfo(): BiometricPrompt.PromptInfo {

        return BiometricPrompt.PromptInfo.Builder()
            .setTitle("Authentication Required")
            .setSubtitle("Log in using Biometric")
            .setDescription("Touch your fingerprint sensor to authenticate")
            .setNegativeButtonText("Use credentials")
            //.setDeviceCredentialAllowed(true)
            //.setConfirmationRequired(true)
            .build()
    }

    private fun authenticateToDecrypt() {
        isEncrypt = false
        if (BiometricManager.from(applicationContext).canAuthenticate() == BiometricManager
                .BIOMETRIC_SUCCESS) {
            // Fetches/generates an instance of SecretKey using [Cipher.DECRYPT_MODE] and
            // then initializes the Cipher with that SecretKey for decryption.
            val cipher = getCipher()
            val secretKey = getSecretKey(keyName)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, initializationVector))
            biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
        }
    }

    private fun transformData(cryptoObject: BiometricPrompt.CryptoObject?) {


        val cipher = cryptoObject?.cipher
        val data = if (isEncrypt) {
            val plainText = editText.text.toString()
            //The Cipher created for encryption and passed to biometric is used here
            val cipherText = cipher!!.doFinal(plainText.toByteArray(Charset.forName("UTF-8")))
            val encryptedData = EncryptedData(cipherText,cipher.iv)
            ciphertext = encryptedData.cipherText
            initializationVector = encryptedData.initializationVector
            String(ciphertext, Charset.forName("UTF-8"))
        } else {
            //The Cipher created for decryption is used here
            val plainText = cipher!!.doFinal(ciphertext)
            String(plainText, Charset.forName("UTF-8"))
        }
        editText.setText(data)
    }

    class EncryptedData(val cipherText: ByteArray, val initializationVector: ByteArray)

    private fun getCipher(): Cipher {
        val transformation = "$encryptionAlgo/$encryptionBlockMode/$encryptionPadding"
        return Cipher.getInstance(transformation)
    }

    private fun getSecretKey(keyName: String): SecretKey {
        // If Secretkey is present for keyName, then return it.
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
