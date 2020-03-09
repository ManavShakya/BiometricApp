package com.example.biometricapp


import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.view.View
import android.widget.Toast
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import kotlinx.android.synthetic.main.activity_main.*
import java.util.concurrent.Executor

class MainActivity : AppCompatActivity() {
    
    private lateinit var executor: Executor
    private lateinit var biometricManager: BiometricManager
    private lateinit var biometricPrompt: BiometricPrompt
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        // Making layout invisible, it will be made visible only after authentication
        mainLayout.visibility = View.GONE
        executor = ContextCompat.getMainExecutor(this)
        biometricManager = BiometricManager.from(this)
        checkHardware(biometricManager)

    }

    /**
     * To check if the user’s device supports biometric features before you perform any authentication.
     */
    private fun checkHardware(biometricManager: BiometricManager) {
        when (biometricManager.canAuthenticate()) {
            BiometricManager.BIOMETRIC_SUCCESS -> authenticateUser(executor)
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> Toast
                .makeText(this, "No hardware detected", Toast.LENGTH_LONG).show()
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> Toast
                .makeText(this, "Biometric features are currently unavailable", Toast.LENGTH_LONG).show()
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> Toast
                .makeText(this, "The user hasn't setup any biometric credentials", Toast.LENGTH_LONG).show()
        }
    }

    private fun authenticateUser(executor: Executor){

        biometricPrompt = BiometricPrompt(this, executor,
            object : BiometricPrompt.AuthenticationCallback() {

                override fun onAuthenticationSucceeded(
                    result: BiometricPrompt.AuthenticationResult
                ) {
                    super.onAuthenticationSucceeded(result)
                    mainLayout.visibility = View.VISIBLE
                }

                override fun onAuthenticationError(
                    errorCode: Int, errString: CharSequence
                ) {
                    super.onAuthenticationError(errorCode, errString)
                    Toast.makeText(
                        applicationContext,
                        "Authentication Error : Kindly Setup a password/PIN and try again",
                        Toast.LENGTH_LONG
                    ).show()

                    finish()

                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    Toast.makeText(applicationContext,
                        "Authentication failed",
                        Toast.LENGTH_SHORT
                    ).show()
                }
            })
            val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Authentication Required")
            .setSubtitle("Log in using Biometric")
            .setDescription("Touch your fingerprint sensor to authenticate")
            .setDeviceCredentialAllowed(true)
            .build()

        biometricPrompt.authenticate(promptInfo)
    }
}
