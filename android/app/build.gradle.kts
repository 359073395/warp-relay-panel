plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.starbridge.panel"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.starbridge.panel"
        minSdk = 29
        targetSdk = 34
        versionCode = 5
        versionName = "2.2.3"

        ndk {
            abiFilters += listOf("arm64-v8a")
        }
    }

    signingConfigs {
        create("release") {
            val ksPath = System.getenv("ANDROID_KEYSTORE_PATH")
            if (!ksPath.isNullOrBlank() && file(ksPath).exists()) {
                storeFile = file(ksPath)
                storePassword = System.getenv("ANDROID_KEYSTORE_PASSWORD") ?: "starbridge"
                keyAlias = System.getenv("ANDROID_KEY_ALIAS") ?: "starbridge"
                keyPassword = System.getenv("ANDROID_KEY_PASSWORD") ?: "starbridge"
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            val ksPath = System.getenv("ANDROID_KEYSTORE_PATH")
            signingConfig = if (!ksPath.isNullOrBlank() && file(ksPath).exists()) {
                signingConfigs.getByName("release")
            } else {
                signingConfigs.getByName("debug")
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    packaging {
        jniLibs {
            useLegacyPackaging = true
        }
    }
}

dependencies {
    implementation(files("libs/hev-socks5-tunnel.aar"))
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
    implementation("org.yaml:snakeyaml:2.2")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
}
