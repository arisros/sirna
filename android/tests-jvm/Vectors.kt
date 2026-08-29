// Cross-target conformance for the Kotlin bindings, on a desktop JVM.
//
// No emulator, no Android SDK, no NDK, no phone. That is the whole point: the
// Android client's agreement with the format is provable long before the app
// exists, and long before any of the ten gigabytes of Android tooling is
// installed anywhere.
//
// A format that three clients each implement will drift. The drift is invisible
// until the day a file written on a phone will not open on a laptop, and by
// then it is in a release. This is the cheapest possible place to catch it.
//
// Mirrors crates/wasm/tests-node/vectors.mjs exactly, including the rule that
// negative cases assert the numeric error code and never the message — codes
// are the contract, messages are UI copy.

import uniffi.sirna_ffi.*
import java.io.File

// The same fixed clock the generator used. A real clock would make the expiry
// vectors start failing on their own.
const val NOW: ULong = 1800000000uL

/** Minimal field reader — enough for a flat manifest, and it keeps this test
 *  free of a JSON dependency that would have to be fetched and pinned. */
fun field(obj: String, name: String): String? {
    val key = "\"$name\""
    val at = obj.indexOf(key)
    if (at < 0) return null
    var i = obj.indexOf(':', at + key.length) + 1
    while (i < obj.length && obj[i].isWhitespace()) i++
    if (obj[i] != '"') {
        val end = obj.indexOfFirst(i) { it == ',' || it == '}' }
        return obj.substring(i, end).trim()
    }
    val sb = StringBuilder()
    i++
    while (obj[i] != '"') {
        if (obj[i] == '\\') i++
        sb.append(obj[i]); i++
    }
    return sb.toString()
}

fun String.indexOfFirst(from: Int, pred: (Char) -> Boolean): Int {
    var i = from
    while (i < length && !pred(this[i])) i++
    return i
}

/** Split the manifest's `vectors` array into one string per object. */
fun splitObjects(json: String): List<String> {
    val start = json.indexOf("\"vectors\"")
    val out = mutableListOf<String>()
    var depth = 0
    var begin = -1
    var i = json.indexOf('[', start)
    while (i < json.length) {
        when (json[i]) {
            '{' -> { if (depth == 0) begin = i; depth++ }
            '}' -> { depth--; if (depth == 0) out.add(json.substring(begin, i + 1)) }
            ']' -> if (depth == 0) return out
        }
        i++
    }
    return out
}

fun main() {
    val root = File(System.getProperty("sirna.vectors") ?: "spec/vectors")
    val manifest = File(root, "vectors.json").readText()

    val declared = field(manifest.substring(0, manifest.indexOf("\"vectors\"")), "format_version")!!
    if (declared.toUByte() != formatVersion()) {
        System.err.println("corpus targets format $declared, this build produces ${formatVersion()}")
        kotlin.system.exitProcess(1)
    }

    var passed = 0
    var failed = 0

    for (v in splitObjects(manifest)) {
        val id = field(v, "id")!!
        val expect = field(v, "expect")!!
        val passphrase = field(v, "passphrase")
        val mnemonic = field(v, "mnemonic")!!
        val plaintextLen = field(v, "plaintext_len")!!.toLong()
        val envelope = File(root, field(v, "envelope_file")!!).readBytes()

        var opened: Opened? = null
        var code: String? = null
        try {
            opened = if (passphrase != null) {
                openEnvelopeWithPassphrase(envelope, passphrase, NOW)
            } else {
                openEnvelope(envelope, mnemonic, NOW)
            }
        } catch (e: SirnaException.Failed) {
            code = e.code.toString()
        }

        if (expect == "ok") {
            when {
                opened == null ->
                    { System.err.println("FAIL $id: expected success, got code $code"); failed++ }
                opened.plaintext.size.toLong() != plaintextLen ->
                    { System.err.println("FAIL $id: length ${opened.plaintext.size} != $plaintextLen"); failed++ }
                else -> passed++
            }
        } else {
            when {
                opened != null ->
                    { System.err.println("FAIL $id: expected error $expect, but it opened"); failed++ }
                code != expect ->
                    { System.err.println("FAIL $id: expected error $expect, got $code"); failed++ }
                else -> passed++
            }
        }
    }

    println("kotlin vectors: $passed passed, $failed failed")
    kotlin.system.exitProcess(if (failed == 0) 0 else 1)
}
