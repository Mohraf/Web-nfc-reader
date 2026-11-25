import javax.inject.Inject

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// The web app lives in the repository root; it is bundled into the APK as assets/www.
val webRootDir: File = rootProject.projectDir.parentFile
val webIncludes = listOf("index.html", "styles.css", "manifest.webmanifest", "icons/**", "js/**")
val bundledUrl = "https://appassets.androidplatform.net/assets/www/index.html"
val startUrl: String = (findProperty("startUrl") as String?)?.takeIf { it.isNotBlank() } ?: bundledUrl

android {
    namespace = "com.chipidreader.app"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.chipidreader.app"
        minSdk = 24
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0"
        buildConfigField("String", "START_URL", "\"$startUrl\"")
    }
    buildFeatures { buildConfig = true }
    buildTypes {
        release {
            isMinifyEnabled = false
            // Demo only: sign release with the debug key so it installs without extra setup.
            signingConfig = signingConfigs.getByName("debug")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}

abstract class CopyWebAssets : DefaultTask() {
    @get:InputFiles @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val sources: ConfigurableFileCollection
    @get:Internal abstract val webRoot: DirectoryProperty
    @get:Input abstract val includes: ListProperty<String>
    @get:OutputDirectory abstract val outputDir: DirectoryProperty
    @get:Inject abstract val fs: FileSystemOperations

    @TaskAction
    fun copy() {
        fs.sync {
            from(webRoot) { include(includes.get()) }
            into(outputDir.dir("www"))
        }
    }
}

val copyWebAssets = tasks.register<CopyWebAssets>("copyWebAssets") {
    webRoot.set(webRootDir)
    includes.set(webIncludes)
    sources.from(fileTree(webRootDir) { include(webIncludes) })
}

androidComponents {
    onVariants { variant ->
        variant.sources.assets?.addGeneratedSourceDirectory(copyWebAssets, CopyWebAssets::outputDir)
    }
}

dependencies {
    implementation("androidx.webkit:webkit:1.11.0")
}
