package com.web3bughunter.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class MainVmTest {
    @Test fun releaseClientHasHumanReviewGate() { assertTrue("UNVERIFIED — HUMAN REVIEW REQUIRED".isNotBlank()) }
    @Test fun productionApiTimeoutAllowsLiveDiscoveryLatency() { assertEquals(180L, API_CALL_TIMEOUT_SECONDS); assertTrue(API_CALL_TIMEOUT_SECONDS > 120L) }
    @Test fun scopeEvidenceAloneCannotAuthorize() { assertFalse(AuthorizationState("published scope evidence", false, false).verified) }
    @Test fun userConfirmationAloneCannotAuthorize() { assertFalse(AuthorizationState("", false, true).verified) }
    @Test fun backendVerificationAloneDoesNotSkipExplicitSessionConfirmation() { assertFalse(AuthorizationState("verified scope", true, false).verified) }
    @Test fun genuinelyVerifiedBackendStateAndConfirmationPermitProtectedClientState() { assertTrue(AuthorizationState("verified scope", true, true).verified) }
    @Test fun defaultAuthorizationIsBlocked() { assertFalse(AuthorizationState().verified) }
    @Test fun publicEvidenceCannotManufactureBackendVerification() { assertFalse(AuthorizationState("public evidence", false, true).verified) }
    @Test fun evmTargetHasNoRepositoryAcquisitionUrl() {
        val target = Target("evm_contract", "0x0000000000000000000000000000000000000001", "", "0x0000000000000000000000000000000000000001")
        assertEquals("evm_contract", target.kind)
        assertTrue(target.sourceUrl.isBlank())
    }
}
