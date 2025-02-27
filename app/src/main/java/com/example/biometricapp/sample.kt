package com.example.biometricapp

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.view.View
import android.widget.Toast
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import java.util.concurrent.Executor

/*this file contains old code for reference
 */
class MyActivity : AppCompatActivity() {

    private lateinit var executor: Executor
    private lateinit var biometricManager: BiometricManager
    private lateinit var biometricPrompt: BiometricPrompt
    private lateinit var mainLayout: View

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        mainLayout = findViewById(R.id.mainLayout)
        mainLayout.visibility = View.GONE
        executor = ContextCompat.getMainExecutor(this)
        biometricManager = BiometricManager.from(this)
        checkHardware(biometricManager)

    }

    /**
     * function to check if the user’s device supports biometric features before you perform any authentication.
     */
    private fun checkHardware(biometricManager: BiometricManager) {
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
                    mainLayout.visibility = View.VISIBLE
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    if (errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON) {
                        //  biometricPrompt.cancelAuthentication()
                    }
                    // Toast.makeText(applicationContext, errString, Toast.LENGTH_LONG).show()
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


}
