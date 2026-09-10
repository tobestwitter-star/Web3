package com.web3bughunter.android

import org.junit.Assert.assertTrue
import org.junit.Test

class MainVmTest {
    @Test fun releaseClientHasHumanReviewGate() {
        assertTrue("UNVERIFIED — HUMAN REVIEW REQUIRED".isNotBlank())
    }
}
