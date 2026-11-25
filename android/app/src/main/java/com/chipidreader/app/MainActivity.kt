package com.chipidreader.app

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.TagLostException
import android.nfc.tech.IsoDep
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import androidx.webkit.JavaScriptReplyProxy
import androidx.webkit.WebViewAssetLoader
import androidx.webkit.WebViewClientCompat
import androidx.webkit.WebViewCompat
import androidx.webkit.WebViewFeature
import org.json.JSONArray
import org.json.JSONObject
import java.io.IOException
import java.util.concurrent.Executors

/**
 * Thin native shell. It hosts the PWA in a WebView and does exactly one thing the web platform
 * cannot: forward raw ISO 7816 APDUs to an ISO-DEP chip (passport / ID card). All protocol logic
 * (BAC, PACE, secure messaging, parsing, verification) stays in the JavaScript app.
 *
 * The bridge object `NfcBridgeNative` is injected only into pages from [allowedOrigins].
 */
class MainActivity : Activity(), NfcAdapter.ReaderCallback {

    private lateinit var webView: WebView
    private var nfc: NfcAdapter? = null
    @Volatile private var isoDep: IsoDep? = null
    private var reply: JavaScriptReplyProxy? = null
    private var readerRequested = false
    private val io = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())

    private val allowedOrigins: Set<String> by lazy {
        val start = Uri.parse(BuildConfig.START_URL)
        setOf("https://${WebViewAssetLoader.DEFAULT_DOMAIN}", "${start.scheme}://${start.authority}")
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        nfc = NfcAdapter.getDefaultAdapter(this)
        WebView.setWebContentsDebuggingEnabled(BuildConfig.DEBUG)

        webView = WebView(this)
        setContentView(webView)
        webView.settings.apply {
            javaScriptEnabled = true
            domStorageEnabled = true
            allowFileAccess = false
            allowContentAccess = false
        }

        val assets = WebViewAssetLoader.Builder()
            .addPathHandler("/assets/", WebViewAssetLoader.AssetsPathHandler(this))
            .build()

        webView.webViewClient = object : WebViewClientCompat() {
            override fun shouldInterceptRequest(view: WebView, request: WebResourceRequest): WebResourceResponse? =
                assets.shouldInterceptRequest(request.url)

            override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
                val origin = "${request.url.scheme}://${request.url.authority}"
                if (origin in allowedOrigins) return false
                startActivity(Intent(Intent.ACTION_VIEW, request.url)) // external links open in the browser
                return true
            }
        }

        if (WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER)) {
            WebViewCompat.addWebMessageListener(webView, "NfcBridgeNative", allowedOrigins) { _, message, _, isMainFrame, proxy ->
                if (isMainFrame) {
                    reply = proxy
                    message.data?.let { handle(it) }
                }
            }
        }
        webView.loadUrl(BuildConfig.START_URL)
    }

    // ------------------------------------------------------------------ page → native
    private fun handle(raw: String) {
        val msg = try { JSONObject(raw) } catch (e: Exception) { return }
        val id = msg.optString("id")
        when (msg.optString("cmd")) {
            "status" -> ok(id, when {
                nfc == null -> "unsupported"
                nfc?.isEnabled != true -> "disabled"
                else -> "ready"
            })
            "start" -> { startReader(); ok(id, true) }
            "stop" -> { stopReader(); ok(id, true) }
            "settings" -> { startActivity(Intent(Settings.ACTION_NFC_SETTINGS)); ok(id, true) }
            "transceive" -> transceive(id, msg.optString("apdu"))
            else -> fail(id, "unknown command")
        }
    }

    private fun transceive(id: String, apduHex: String) {
        val apdu = try { hexToBytes(apduHex) } catch (e: Exception) { fail(id, "bad APDU hex"); return }
        io.execute {
            val dep = isoDep
            try {
                if (dep == null || !dep.isConnected) throw TagLostException("No chip connected")
                val resp = dep.transceive(apdu)
                main.post { ok(id, bytesToHex(resp)) }
            } catch (e: TagLostException) {
                main.post { fail(id, "Tag lost"); event(JSONObject().put("event", "tagLost")) }
            } catch (e: Exception) {
                main.post { fail(id, e.message ?: e.javaClass.simpleName) }
            }
        }
    }

    // ------------------------------------------------------------------ NFC reader mode
    private fun startReader() {
        val adapter = nfc ?: return
        readerRequested = true
        val extras = Bundle().apply { putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 1000) }
        adapter.enableReaderMode(
            this, this,
            NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_NFC_B or NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK,
            extras,
        )
    }

    private fun stopReader() {
        readerRequested = false
        closeTag()
        nfc?.disableReaderMode(this)
    }

    override fun onTagDiscovered(tag: Tag) {
        val dep = IsoDep.get(tag)
        if (dep == null) {
            main.post { event(JSONObject().put("event", "error").put("message", "This tag is not a smart-card chip (no ISO-DEP). Passports and ID cards use ISO-DEP.")) }
            return
        }
        try {
            dep.connect()
            dep.timeout = 5000 // PACE / signature steps can take a while on older chips
            closeTag()
            isoDep = dep
            val info = JSONObject()
                .put("technology", "IsoDep")
                .put("uid", bytesToHex(tag.id))
                .put("techList", JSONArray(tag.techList.toList()))
                .put("historicalBytes", dep.historicalBytes?.let { bytesToHex(it) } ?: JSONObject.NULL)
                .put("hiLayerResponse", dep.hiLayerResponse?.let { bytesToHex(it) } ?: JSONObject.NULL)
                .put("maxTransceiveLength", dep.maxTransceiveLength)
                .put("extendedLength", dep.isExtendedLengthApduSupported)
            main.post { event(JSONObject().put("event", "tag").put("info", info)) }
        } catch (e: IOException) {
            main.post { event(JSONObject().put("event", "error").put("message", "Could not connect to the chip: ${e.message}")) }
        }
    }

    private fun closeTag() {
        try { isoDep?.close() } catch (_: IOException) { }
        isoDep = null
    }

    // ------------------------------------------------------------------ native → page
    private fun ok(id: String, result: Any) = send(JSONObject().put("id", id).put("ok", true).put("result", result))
    private fun fail(id: String, error: String) = send(JSONObject().put("id", id).put("ok", false).put("error", error))
    private fun event(obj: JSONObject) = send(obj)
    private fun send(obj: JSONObject) { reply?.postMessage(obj.toString()) }

    // ------------------------------------------------------------------ lifecycle
    override fun onResume() {
        super.onResume()
        if (readerRequested) startReader()
    }

    override fun onPause() {
        super.onPause()
        nfc?.disableReaderMode(this) // must be re-enabled while resumed
    }

    override fun onDestroy() {
        closeTag()
        io.shutdownNow()
        webView.destroy()
        super.onDestroy()
    }

    @Deprecated("Deprecated in Java")
    override fun onBackPressed() {
        if (webView.canGoBack()) webView.goBack() else @Suppress("DEPRECATION") super.onBackPressed()
    }

    private companion object {
        fun bytesToHex(b: ByteArray): String = b.joinToString("") { "%02X".format(it) }
        fun hexToBytes(s: String): ByteArray {
            val clean = s.filter { !it.isWhitespace() }
            require(clean.length % 2 == 0)
            return ByteArray(clean.length / 2) { clean.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
        }
    }
}
