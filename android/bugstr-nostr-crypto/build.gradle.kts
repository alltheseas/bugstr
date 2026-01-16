plugins {
    kotlin("jvm")
}

group = "com.bugstr"
version = "0.1.0-SNAPSHOT"

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(21))
    }
}

dependencies {
    implementation("com.vitorpamplona.quartz:quartz:1.03.0")

    testImplementation(kotlin("test"))
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.10.2")
}

tasks.test {
    useJUnitPlatform()
}
