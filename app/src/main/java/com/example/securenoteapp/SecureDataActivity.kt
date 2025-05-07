package com.example.securenoteapp

import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.util.Log
import android.widget.Toast
import android.view.WindowManager
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.security.crypto.EncryptedFile
import androidx.security.crypto.MasterKeys
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume

private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
private const val MASTER_KEY_ALIAS = "_androidx_security_master_key_"
private const val ENCRYPTED_FILE_NAME = "secure_notes_data.enc"
private const val EXPORT_FILE_NAME = "secure_notes_export.bak"

private const val PBE_ITERATION_COUNT = 65536
private const val PBE_KEY_LENGTH = 256 // AES-256
private const val PBE_SALT_LENGTH = 16
private const val GCM_IV_LENGTH = 12
private const val GCM_TAG_LENGTH = 128

private const val TAG = "SecureNoteApp"

class SecureDataActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            setRecentsScreenshotEnabled(false)
        }
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                SecureNotesScreen(activity = this)
            }
        }
    }
}

@Composable
fun SecureNotesScreen(activity: FragmentActivity) {
    var noteContent by remember { mutableStateOf("") }
    var passwordInput by remember { mutableStateOf("") }
    var showPasswordDialog by remember { mutableStateOf(false) }
    var isExportDialog by remember { mutableStateOf(false) }
    var importUri by remember { mutableStateOf<Uri?>(null) }

    val context = LocalContext.current
    val focusManager = LocalFocusManager.current
    val coroutineScope = rememberCoroutineScope()
//    val activity = LocalContext.current as FragmentActivity // Dla BiometricPrompt

    suspend fun prepareExportDataInBackground(ctx: android.content.Context, pass: String): Uri? {
        Log.d(TAG, "Starting prepareExportDataInBackground...")
        if (pass.isBlank()) {
            Log.w(TAG, "prepareExportDataInBackground: Password is empty.")
            withContext(Dispatchers.Main) { showToast(ctx, "Password cannot be empty for export.") }
            return null
        }

        return withContext(Dispatchers.IO) {
            val currentData = try {
                loadEncryptedDataInternal(ctx)
            } catch (e: Exception) {
                Log.e(TAG, "prepareExportDataInBackground: Error loading data to export", e)
                null
            }

            if (currentData == null) {
                Log.w(TAG, "prepareExportDataInBackground: currentData is null, cannot export.")
                withContext(Dispatchers.Main) { showToast(ctx, "Cannot export empty or unreadable note.") }
                return@withContext null
            }

            var outputStream: FileOutputStream? = null
            var tempFileUri: Uri? = null
            val tempExportFile = File(ctx.cacheDir, "temp_${System.currentTimeMillis()}_${EXPORT_FILE_NAME}")

            try {
                Log.d(TAG, "prepareExportDataInBackground: Preparing data...")
                val salt = ByteArray(PBE_SALT_LENGTH).apply { SecureRandom().nextBytes(this) }
                val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                val spec = PBEKeySpec(pass.toCharArray(), salt, PBE_ITERATION_COUNT, PBE_KEY_LENGTH)
                val secretKeyBytes = factory.generateSecret(spec).encoded
                val secretKey = SecretKeySpec(secretKeyBytes, "AES")
                spec.clearPassword()

                val iv = ByteArray(GCM_IV_LENGTH).apply { SecureRandom().nextBytes(this) }
                val gcmParameterSpec = GCMParameterSpec(GCM_TAG_LENGTH, iv)

                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec)
                val encryptedData = cipher.doFinal(currentData.toByteArray(StandardCharsets.UTF_8))

                outputStream = FileOutputStream(tempExportFile)
                outputStream.write(salt)
                outputStream.write(iv)
                outputStream.write(encryptedData)
                outputStream.flush()
                tempFileUri = Uri.fromFile(tempExportFile)
                Log.d(TAG, "prepareExportDataInBackground: Temp file written. Size: ${tempExportFile.length()}, URI: $tempFileUri")

            } catch (e: Exception) {
                Log.e(TAG, "prepareExportDataInBackground: Error during preparation", e)
                withContext(Dispatchers.Main) { showToast(ctx, "Error preparing export data: ${e.message}") }
                tempExportFile.delete()
                tempFileUri = null
            } finally {
                try {
                    outputStream?.close()
                } catch (ioe: IOException) {
                    Log.e(TAG, "prepareExportDataInBackground: Error closing temp file stream", ioe)
                }
            }
            Log.d(TAG, "prepareExportDataInBackground: Returning temp URI: $tempFileUri")
            tempFileUri
        }
    }

    val fileExporter = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("application/octet-stream")
    ) { targetUri ->
        targetUri?.let { safeTargetUri ->
            Log.d(TAG, "fileExporter.onResult: Received target URI: $safeTargetUri")
            coroutineScope.launch(Dispatchers.IO) {
                Log.d(TAG, "fileExporter.onResult: Coroutine started for writing.")
                var success = false
                val tempFileUri = prepareExportDataInBackground(context, passwordInput)
                Log.d(TAG, "fileExporter.onResult: Received tempFileUri: $tempFileUri")

                if (tempFileUri != null) {
                    val tempFilePath = try { tempFileUri.path } catch (e: Exception) { null }

                    if (tempFilePath == null) {
                        Log.e(TAG, "fileExporter.onResult: Temp file path is null!")
                        withContext(Dispatchers.Main) { showToast(context, "Error getting temporary file path.") }
                        try { File(tempFileUri.toString()).delete() } catch (_: Exception) {}
                        return@launch
                    }

                    val tempFile = File(tempFilePath)
                    Log.d(TAG, "fileExporter.onResult: Temp file exists: ${tempFile.exists()}, length: ${tempFile.length()}")

                    if (!tempFile.exists() || tempFile.length() == 0L) {
                        Log.w(TAG, "fileExporter.onResult: Temp file is missing or empty before copy!")
                    }

                    if (tempFile.exists() && tempFile.length() > 0) {
                        try {
                            Log.d(TAG, "fileExporter.onResult: Attempting to copy to target URI...")
                            context.contentResolver.openOutputStream(safeTargetUri)?.use { outputStream ->
                                FileInputStream(tempFile).use { inputStream ->
                                    val bytesCopied = inputStream.copyTo(outputStream)
                                    Log.d(TAG, "fileExporter.onResult: Copy finished. Bytes copied: $bytesCopied")
                                    success = bytesCopied > 0
                                }
                            } ?: run {
                                Log.e(TAG, "fileExporter.onResult: Failed to open output stream for target URI")
                                throw IOException("Failed to open output stream for target URI")
                            }
                        } catch (e: Exception) {
                            Log.e(TAG, "fileExporter.onResult: Error writing export file", e)
                            withContext(Dispatchers.Main) { showToast(context, "Error writing export file: ${e.message}") }
                        } finally {
                            Log.d(TAG, "fileExporter.onResult: Deleting temp file: ${tempFile.path}")
                            tempFile.delete()
                        }
                    } else {
                        Log.w(TAG, "fileExporter.onResult: Skipping copy because temp file is missing or empty.")
                    }
                } else {
                    Log.w(TAG, "fileExporter.onResult: tempFileUri was null, skipping copy.")
                }

                withContext(Dispatchers.Main) {
                    Log.d(TAG, "fileExporter.onResult: Showing result. Success: $success")
                    if (success) {
                        showToast(context, "Export successful!")
                    } else {
                        showToast(context, "Export failed.")
                    }
                    passwordInput = ""
                }
            }
        } ?: run {
            Log.w(TAG, "fileExporter.onResult: Target URI was null (User canceled?).")
            coroutineScope.launch(Dispatchers.Main) {
                passwordInput = ""
                isExportDialog = false
                showPasswordDialog = false
            }
        }
    }


    val fileImporter = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent(),
        onResult = { uri ->
            uri?.let { sourceUri ->
                Log.d(TAG, "fileImporter.onResult: Received source URI: $sourceUri")
                importUri = sourceUri
                isExportDialog = false
                passwordInput = ""
                showPasswordDialog = true
            } ?: run {
                Log.w(TAG, "fileImporter.onResult: User canceled file selection.")
                importUri = null
            }
        }
    )


    Surface(
        modifier = Modifier.fillMaxSize(),
        color = Color(0xFFEEF6FB)
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(
                text = "Secure Notes",
                fontSize = 24.sp,
                fontWeight = FontWeight.Bold,
                color = Color(0xFF004D99)
            )
            Spacer(modifier = Modifier.height(16.dp))

            OutlinedTextField(
                value = noteContent,
                onValueChange = { noteContent = it },
                label = { Text("Your secure note") },
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 150.dp),
                shape = RoundedCornerShape(8.dp),
                textStyle = TextStyle(fontSize = 16.sp),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = Color(0xFF2196F3),
                    unfocusedBorderColor = Color.Gray,
                )
            )
            Spacer(modifier = Modifier.height(16.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceEvenly
            ) {
                Button(
                    onClick = {
                        focusManager.clearFocus()
                        coroutineScope.launch {
                            val authenticated = showBiometricPrompt(
                                activity, // Użyj activity
                                "Authenticate to Save Note",
                                "Confirm your identity to save the note."
                            )
                            if (authenticated) {
                                saveEncryptedData(context, noteContent) {
                                    showToast(context, "Note saved securely")
                                }
                            } else {
                                showToast(context, "Authentication failed. Note not saved.")
                            }
                        }
                    },
                    shape = RoundedCornerShape(8.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF1E88E5))
                ) { Text("Save Note") }

                Button(
                    onClick = {
                        focusManager.clearFocus()
                        coroutineScope.launch {
                            // POCZĄTEK ZMIANY
                            val authenticated = showBiometricPrompt(
                                activity, // Użyj activity
                                "Authenticate to Load Note",
                                "Confirm your identity to load the note."
                            )
                            if (authenticated) {
                                // KONIEC ZMIANY
                                val loadedData = loadEncryptedData(context)
                                if (loadedData != null) {
                                    noteContent = loadedData
                                    showToast(context, "Note loaded")
                                } else {
                                    // Komunikat już pokazany lub autoryzacja nie powiodła się
                                }
                                // POCZĄTEK ZMIANY
                            } else {
                                showToast(context, "Authentication failed. Note not loaded.")
                            }
                            // KONIEC ZMIANY
                        }
                    },
                    // ...
                ) { Text("Load Note") }
            }
            Spacer(modifier = Modifier.height(16.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceEvenly
            ) {
                Button(
                    onClick = {
                        isExportDialog = true
                        passwordInput = ""
                        showPasswordDialog = true
                        Log.d(TAG, "Export button clicked, showing password dialog.")
                    },
                    shape = RoundedCornerShape(8.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFFF9800))
                ) { Text("Export") }

                Button(
                    onClick = {
                        Log.d(TAG, "Import button clicked, launching file picker.")
                        fileImporter.launch("*/*")
                    },
                    shape = RoundedCornerShape(8.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF673AB7))
                ) { Text("Import") }

                Button(
                    onClick = {
                        coroutineScope.launch {
                            // POCZĄTEK ZMIANY
                            val authenticated = showBiometricPrompt(
                                activity, // Użyj activity
                                "Authenticate to Clear Data",
                                "Confirm your identity to clear all notes."
                            )
                            if (authenticated) {
                                // KONIEC ZMIANY
                                if (clearSecureData(context)) {
                                    noteContent = ""
                                    showToast(context, "Data cleared successfully")
                                } else {
                                    // Komunikat już pokazany
                                }
                                // POCZĄTEK ZMIANY
                            } else {
                                showToast(context, "Authentication failed. Data not cleared.")
                            }
                            // KONIEC ZMIANY
                        }
                    },
                    // ...
                ) { Text("Clear Data") }
            }
        }

        if (showPasswordDialog) {
            AlertDialog(
                onDismissRequest = {
                    showPasswordDialog = false
                    passwordInput = ""
                    isExportDialog = false
                    Log.d(TAG, "Password dialog dismissed.")
                },
                title = { Text(if (isExportDialog) "Export Password" else "Import Password") },
                text = {
                    OutlinedTextField(
                        value = passwordInput,
                        onValueChange = { passwordInput = it },
                        label = { Text("Enter password") },
                        singleLine = true
                        // Consider adding: keyboardType = KeyboardType.Password, visualTransformation = PasswordVisualTransformation()
                    )
                },
                confirmButton = {
                    Button(
                        enabled = passwordInput.isNotBlank(),
                        onClick = {
                            Log.d(TAG, "Password dialog OK clicked. IsExport: $isExportDialog")
                            if (isExportDialog) {
                                Log.d(TAG, "Launching file exporter...")
                                fileExporter.launch(EXPORT_FILE_NAME)
                                showPasswordDialog = false
                            } else {
                                if (passwordInput.isNotBlank()) {
                                    val currentSourceUri = importUri
                                    if (currentSourceUri != null) {
                                        Log.d(TAG, "Starting import coroutine...")
                                        coroutineScope.launch {
                                            val importedData = importDataWithPassword(context, currentSourceUri, passwordInput)
                                            if (importedData != null) {
                                                // POCZĄTEK ZMIANY
                                                val authenticated = showBiometricPrompt(
                                                    activity, // Użyj activity
                                                    "Authenticate to Save Imported Note",
                                                    "Confirm your identity to save the imported note."
                                                )
                                                if (authenticated) {
                                                    // KONIEC ZMIANY
                                                    saveEncryptedData(context, importedData) {
                                                        noteContent = importedData
                                                        showToast(context, "Data imported and saved successfully!")
                                                        Log.d(TAG, "Import successful and saved.")
                                                    }
                                                    // POCZĄTEK ZMIANY
                                                } else {
                                                    showToast(context, "Authentication failed. Imported data not saved.")
                                                }
                                                // KONIEC ZMIANY
                                            } else {
                                                // Toast dla niepowodzenia importu już pokazany
                                                Log.w(TAG, "Import failed (importDataWithPassword returned null).")
                                            }
                                            passwordInput = ""
                                            importUri = null
                                        }
                                    } else {
                                        Log.e(TAG, "Import OK clicked, but importUri is null!")
                                        showToast(context, "Error: No file selected for import.")
                                    }
                                }
                                showPasswordDialog = false
                            }
                        }
                    ) { Text("OK") }
                },
                dismissButton = {
                    Button(onClick = {
                        showPasswordDialog = false
                        passwordInput = ""
                        isExportDialog = false
                        Log.d(TAG, "Password dialog Cancel clicked.")
                    }) { Text("Cancel") }
                }
            )
        }
    }
}

fun showToast(context: android.content.Context, message: String) {
    Toast.makeText(context, message, Toast.LENGTH_SHORT).show()
}

// New suspend function for biometric authentication
private suspend fun showBiometricPrompt(
    activity: FragmentActivity, // Requires FragmentActivity
    title: String,
    subtitle: String
): Boolean = suspendCancellableCoroutine { continuation ->
    val executor = ContextCompat.getMainExecutor(activity)
    val biometricManager = BiometricManager.from(activity)

    val promptInfo = BiometricPrompt.PromptInfo.Builder()
        .setTitle(title)
        .setSubtitle(subtitle)
        .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL)
        .build()

    val biometricPrompt = BiometricPrompt(activity, executor,
        object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                Log.d(TAG, "Biometric authentication succeeded.")
                if (continuation.isActive) continuation.resume(true)
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                super.onAuthenticationError(errorCode, errString)
                Log.e(TAG, "Biometric authentication error: $errorCode - $errString")
                val userMessage = when (errorCode) {
                    BiometricPrompt.ERROR_NEGATIVE_BUTTON,
                    BiometricPrompt.ERROR_USER_CANCELED -> "Authentication canceled."
                    BiometricPrompt.ERROR_NO_BIOMETRICS -> "No biometrics enrolled."
                    BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL -> "No device credential (PIN, pattern, password) set up."
                    else -> "Authentication error: $errString"
                }
                activity.runOnUiThread { // Ensure toast is on main thread
                    showToast(activity, userMessage)
                }
                if (continuation.isActive) continuation.resume(false)
            }

            override fun onAuthenticationFailed() {
                super.onAuthenticationFailed()
                Log.w(TAG, "Biometric authentication failed (not recognized).")
                activity.runOnUiThread { // Ensure toast is on main thread
                    showToast(activity, "Authentication failed. Not recognized.")
                }
                if (continuation.isActive) continuation.resume(false)
            }
        })

    when (biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL)) {
        BiometricManager.BIOMETRIC_SUCCESS -> {
            Log.d(TAG, "Authentication is available. Showing prompt.")
            biometricPrompt.authenticate(promptInfo)
        }
        BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> {
            Log.e(TAG, "No biometric hardware.")
            showToast(activity, "No biometric hardware available on this device.")
            if (continuation.isActive) continuation.resume(false)
        }
        BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> {
            Log.e(TAG, "Biometric hardware unavailable.")
            showToast(activity, "Biometric features are currently unavailable.")
            if (continuation.isActive) continuation.resume(false)
        }
        BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> {
            Log.e(TAG, "No biometrics enrolled and no device credential set.")
            showToast(activity, "Please set up a screen lock (PIN, pattern, or password) or enroll biometrics in your device settings.")
            if (continuation.isActive) continuation.resume(false)
        }
        else -> {
            Log.e(TAG, "Biometric authentication not available for other reasons.")
            showToast(activity, "Biometric authentication is not available.")
            if (continuation.isActive) continuation.resume(false)
        }
    }

    continuation.invokeOnCancellation {
        Log.d(TAG, "Biometric prompt coroutine cancelled.")
    }
}

private fun getOrCreateMasterKey(): String {
    val keyGenParameterSpec = MasterKeys.AES256_GCM_SPEC
    return MasterKeys.getOrCreate(keyGenParameterSpec)
}

suspend fun saveEncryptedData(context: android.content.Context, data: String, onSuccess: () -> Unit) {
    withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "saveEncryptedData: Saving data...")
            val masterKeyAlias = getOrCreateMasterKey()
            val file = File(context.filesDir, ENCRYPTED_FILE_NAME)

            if (file.exists()) {
                Log.d(TAG, "saveEncryptedData: Output file exists, deleting before overwrite.")
                val deleted = file.delete()
                if (!deleted) {
                    Log.w(TAG, "saveEncryptedData: Failed to delete existing file! Proceeding anyway...")
                }
            }

            val encryptedFile = EncryptedFile.Builder(
                file,
                context,
                masterKeyAlias,
                EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
            ).build()

            encryptedFile.openFileOutput().use { outputStream ->
                outputStream.write(data.toByteArray(StandardCharsets.UTF_8))
                outputStream.flush()
            }
            Log.d(TAG, "saveEncryptedData: Data saved successfully.")
            withContext(Dispatchers.Main) { onSuccess() }
        } catch (e: Exception) {
            Log.e(TAG, "saveEncryptedData: Error saving data", e)
            withContext(Dispatchers.Main) { showToast(context, "Error saving data: ${e.message}") }
        }
    }
}

// Internal load function without biometric prompt, for use by export.
private suspend fun loadEncryptedDataInternal(context: android.content.Context): String? {
    return withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "loadEncryptedDataInternal: Loading data...")
            val masterKeyAlias = getOrCreateMasterKey()
            val file = File(context.filesDir, ENCRYPTED_FILE_NAME)

            if (!file.exists()) {
                Log.w(TAG, "loadEncryptedDataInternal: Data file not found.")
                return@withContext null
            }

            val encryptedFile = EncryptedFile.Builder(
                file,
                context,
                masterKeyAlias,
                EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
            ).build()

            val data = encryptedFile.openFileInput().use { inputStream ->
                val bytes = inputStream.readBytes()
                String(bytes, StandardCharsets.UTF_8)
            }
            Log.d(TAG, "loadEncryptedDataInternal: Data loaded successfully. Length: ${data.length}")
            data
        } catch (e: Exception) {
            Log.e(TAG, "loadEncryptedDataInternal: Error loading data", e)
            withContext(Dispatchers.Main) { showToast(context, "Error loading internal data: ${e.message}") }
            null
        }
    }
}

suspend fun loadEncryptedData(context: android.content.Context): String? {
    // Biometric check is now done *before* calling this function in the UI.
    return loadEncryptedDataInternal(context) // ZMIANA: Wywołuje wersję wewnętrzną
}

suspend fun clearSecureData(context: android.content.Context): Boolean {
    return withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "clearSecureData: Clearing data...")
            val file = File(context.filesDir, ENCRYPTED_FILE_NAME)
            var deleted = false
            if (file.exists()) {
                deleted = file.delete()
                Log.d(TAG, "clearSecureData: File deletion attempt result: $deleted")
            } else {
                Log.d(TAG, "clearSecureData: File did not exist.")
                deleted = true
            }
            deleted
        } catch (e: Exception) {
            Log.e(TAG, "clearSecureData: Error clearing data", e)
            withContext(Dispatchers.Main) { showToast(context, "Error clearing data: ${e.message}") }
            false
        }
    }
}

suspend fun importDataWithPassword(context: android.content.Context, sourceUri: Uri, password: String): String? {
    Log.d(TAG, "importDataWithPassword: Starting import from URI: $sourceUri")
    if (password.isBlank()) {
        Log.w(TAG, "importDataWithPassword: Password is empty.")
        withContext(Dispatchers.Main) { showToast(context, "Password cannot be empty for import.") }
        return null
    }
    return withContext(Dispatchers.IO) {
        var inputStream: InputStream? = null
        try {
            inputStream = context.contentResolver.openInputStream(sourceUri)
            if (inputStream == null) {
                Log.e(TAG, "importDataWithPassword: Cannot open input stream for URI: $sourceUri")
                withContext(Dispatchers.Main) { showToast(context, "Cannot open import file.") }
                return@withContext null
            }

            val salt = ByteArray(PBE_SALT_LENGTH)
            val iv = ByteArray(GCM_IV_LENGTH)

            val saltRead = inputStream.read(salt)
            val ivRead = inputStream.read(iv)
            Log.d(TAG, "importDataWithPassword: Bytes read for salt: $saltRead (expected $PBE_SALT_LENGTH), for IV: $ivRead (expected $GCM_IV_LENGTH)")

            if (saltRead != PBE_SALT_LENGTH || ivRead != GCM_IV_LENGTH) {
                Log.e(TAG, "importDataWithPassword: Invalid file format - incorrect salt/IV length.")
                throw IOException("Invalid file format: couldn't read salt or IV.")
            }

            val encryptedData = inputStream.readBytes()
            Log.d(TAG, "importDataWithPassword: Read encrypted data length: ${encryptedData.size}")
            if (encryptedData.isEmpty()) {
                Log.w(TAG, "importDataWithPassword: Encrypted data part is empty.")
                throw IOException("Invalid file format: encrypted data is empty.")
            }

            Log.d(TAG, "importDataWithPassword: Deriving key from password...")
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            val spec = PBEKeySpec(password.toCharArray(), salt, PBE_ITERATION_COUNT, PBE_KEY_LENGTH)
            val secretKeyBytes = factory.generateSecret(spec).encoded
            val secretKey = SecretKeySpec(secretKeyBytes, "AES")
            spec.clearPassword()

            Log.d(TAG, "importDataWithPassword: Decrypting data...")
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val gcmParameterSpec = GCMParameterSpec(GCM_TAG_LENGTH, iv)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec)

            val decryptedDataBytes = cipher.doFinal(encryptedData)
            val result = String(decryptedDataBytes, StandardCharsets.UTF_8)
            Log.d(TAG, "importDataWithPassword: Decryption successful. Result length: ${result.length}")
            result

        } catch (e: Exception) {
            Log.e(TAG, "importDataWithPassword: Error during import", e)
            val errorMsg = when (e) {
                is javax.crypto.AEADBadTagException -> "Import Error: Invalid password or corrupted file."
                is IOException -> "Import Error: Problem reading file (${e.message})"
                else -> "Import Error: ${e.message}"
            }
            withContext(Dispatchers.Main) { showToast(context, errorMsg) }
            null
        } finally {
            try {
                inputStream?.close()
            } catch (ioe: IOException) {
                Log.e(TAG, "importDataWithPassword: Error closing import stream", ioe)
            }
        }
    }
}