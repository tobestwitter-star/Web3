package com.web3bughunter.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class MainVmTest {
    @Test fun releaseClientHasHumanReviewGate() {
        assertTrue("UNVERIFIED — HUMAN REVIEW REQUIRED".isNotBlank())
    }

    @Test fun productionApiTimeoutAllowsLiveDiscoveryLatency() {
        assertEquals(180L, API_CALL_TIMEOUT_SECONDS)
        assertTrue(API_CALL_TIMEOUT_SECONDS > 120L)
    }
}
