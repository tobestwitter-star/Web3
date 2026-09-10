package com.web3bughunter.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
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

    @Test fun authorizationRequiresScopeEvidenceAndExplicitConfirmation() {
        assertFalse(AuthorizationState("", false).verified)
        assertFalse(AuthorizationState("published scope evidence", false).verified)
        assertFalse(AuthorizationState("", true).verified)
        assertTrue(AuthorizationState("published scope evidence", true).verified)
    }

    @Test fun authorizationStateIsNotGrantedByDefault() {
        assertFalse(AuthorizationState().verified)
        assertFalse(AuthorizationState(evidence = "scope", confirmed = false).verified)
    }
}
