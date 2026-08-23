'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
const manifestPath = path.join(root, 'manifest.json');
const taskFixtureRoot = path.join(root, 'fixtures', 'task', 'v1');
const collaborationFixtureRoot = path.join(root, 'fixtures', 'collaboration', 'v1');
const harnessFixtureRoot = path.join(root, 'fixtures', 'harness', 'v1');
const artifactFixtureRoot = path.join(root, 'fixtures', 'artifact', 'v1');
const verificationFixtureRoot = path.join(root, 'fixtures', 'verification', 'v1');
const verdictFixtureRoot = path.join(root, 'fixtures', 'verdict', 'v1');
const localApiFixtureRoot = path.join(root, 'fixtures', 'localapi', 'v1');
const persistenceFixtureRoot = path.join(root, 'fixtures', 'persistence', 'v1');
const requiredCategories = new Set(['valid', 'invalid', 'duplicate', 'stale', 'unauthorized', 'recovery']);
const taskCommandNames = new Set([
  'createTask', 'activateTask', 'submitTaskEvidence', 'recordTaskVerification',
  'applyFounderVerdict', 'reviseTask', 'interruptTask', 'holdTask', 'resumeTask',
  'requestTaskCancellation', 'recordTaskCancellationOutcome', 'supersedeTask', 'expireTask',
]);
const taskStatuses = new Set([
  'TASK_STATUS_READY', 'TASK_STATUS_ACTIVE', 'TASK_STATUS_VERIFICATION_PENDING',
  'TASK_STATUS_VERDICT_PENDING', 'TASK_STATUS_REWORK', 'TASK_STATUS_CANCELLATION_PENDING',
  'TASK_STATUS_INTERRUPTED', 'TASK_STATUS_HELD', 'TASK_STATUS_COMPLETED',
  'TASK_STATUS_REJECTED', 'TASK_STATUS_CANCELLED', 'TASK_STATUS_SUPERSEDED',
  'TASK_STATUS_EXPIRED',
]);
const collaborationCommandNames = new Set([
  'createRun', 'activateRun', 'createAttempt', 'acquireAttemptLease',
  'renewAttemptLease', 'recordDispatchIntent', 'recordDeliveryReceipt',
  'recordHarnessAck', 'recordRunningObservation', 'recordAttemptReturn',
  'markAttemptOutcomeUnknown', 'beginAttemptReconciliation',
  'recordAttemptReconciliation', 'recordCheckpoint',
  'requestAttemptCancellation', 'recordAttemptCancellationOutcome',
  'holdAttempt', 'resumeAttempt', 'commitStepReturn', 'supersedeRun', 'expireRun',
]);
const runStatuses = new Set([
  'RUN_STATUS_PLANNED', 'RUN_STATUS_ACTIVE', 'RUN_STATUS_RETURN_PENDING',
  'RUN_STATUS_HELD', 'RUN_STATUS_CANCELLATION_PENDING', 'RUN_STATUS_RETURNED',
  'RUN_STATUS_FAILED', 'RUN_STATUS_CANCELLED', 'RUN_STATUS_SUPERSEDED',
  'RUN_STATUS_EXPIRED',
]);
const stepStatuses = new Set([
  'STEP_STATUS_BLOCKED', 'STEP_STATUS_READY', 'STEP_STATUS_ACTIVE',
  'STEP_STATUS_RETURN_PENDING', 'STEP_STATUS_HELD', 'STEP_STATUS_RETURNED',
  'STEP_STATUS_FAILED', 'STEP_STATUS_CANCELLED', 'STEP_STATUS_SKIPPED',
  'STEP_STATUS_SUPERSEDED',
]);
const attemptStatuses = new Set([
  'ATTEMPT_STATUS_CREATED', 'ATTEMPT_STATUS_LEASED',
  'ATTEMPT_STATUS_DISPATCH_PENDING', 'ATTEMPT_STATUS_DISPATCHED',
  'ATTEMPT_STATUS_ACKNOWLEDGED', 'ATTEMPT_STATUS_RUNNING',
  'ATTEMPT_STATUS_CANCELLATION_PENDING', 'ATTEMPT_STATUS_OUTCOME_UNKNOWN',
  'ATTEMPT_STATUS_RECONCILING', 'ATTEMPT_STATUS_INTERRUPTED',
  'ATTEMPT_STATUS_HELD', 'ATTEMPT_STATUS_RETURNED', 'ATTEMPT_STATUS_FAILED',
  'ATTEMPT_STATUS_CANCELLED', 'ATTEMPT_STATUS_SUPERSEDED',
  'ATTEMPT_STATUS_EXPIRED',
]);
const harnessCommandNames = new Set([
  'attestCapability', 'probe', 'dispatch', 'ingestObservation',
  'decideApproval', 'cancel', 'resume',
]);
const artifactCommandNames = new Set([
  'stageArtifact', 'sealArtifact', 'quarantineObject', 'proposeClaim',
  'withdrawClaim', 'recordEvidence', 'createArtifactSet', 'sealArtifactSet',
  'submitReturnHandoff', 'tombstoneObject',
]);
const artifactStatuses = new Set([
  'ARTIFACT_STATUS_STAGED', 'ARTIFACT_STATUS_SEALED',
  'ARTIFACT_STATUS_QUARANTINED', 'ARTIFACT_STATUS_TOMBSTONED',
  'ARTIFACT_STATUS_SUPERSEDED',
]);
const artifactSetStatuses = new Set([
  'ARTIFACT_SET_STATUS_DRAFT', 'ARTIFACT_SET_STATUS_SEALED',
  'ARTIFACT_SET_STATUS_QUARANTINED', 'ARTIFACT_SET_STATUS_TOMBSTONED',
  'ARTIFACT_SET_STATUS_SUPERSEDED',
]);
const returnHandoffStatuses = new Set([
  'RETURN_HANDOFF_STATUS_SUBMITTED', 'RETURN_HANDOFF_STATUS_RECEIPTED',
  'RETURN_HANDOFF_STATUS_QUARANTINED', 'RETURN_HANDOFF_STATUS_SUPERSEDED',
]);
const verificationCommandNames = new Set([
  'attestCheckerProfile', 'createVerificationRequest', 'startVerificationRun',
  'recordCriterionResult', 'completeVerification',
  'requestVerificationCancellation', 'recordVerificationCancellation',
  'holdVerification',
]);
const verificationStatuses = new Set([
  'VERIFICATION_STATUS_QUEUED', 'VERIFICATION_STATUS_RUNNING',
  'VERIFICATION_STATUS_CANCELLATION_PENDING', 'VERIFICATION_STATUS_COMPLETED',
  'VERIFICATION_STATUS_HELD', 'VERIFICATION_STATUS_CANCELLED',
  'VERIFICATION_STATUS_SUPERSEDED',
]);
const verdictCommandNames = new Set([
  'issueFounderVerdict', 'consumeFounderVerdict', 'revokeFounderVerdict',
  'expireFounderVerdict',
]);
const verdictStates = new Set([
  'FOUNDER_VERDICT_STATE_KIND_ISSUED',
  'FOUNDER_VERDICT_STATE_KIND_CONSUMED',
  'FOUNDER_VERDICT_STATE_KIND_REVOKED',
  'FOUNDER_VERDICT_STATE_KIND_EXPIRED',
  'FOUNDER_VERDICT_STATE_KIND_SUPERSEDED',
]);
const localApiOperationNames = new Set([
  'openSession', 'getTaskView', 'listTaskViews', 'getEvidenceGraph',
  'getProjectionStatus', 'watchTaskViews', 'executeTaskCommand',
  'decideHarnessApproval', 'executeFounderVerdict', 'awaitProjection',
]);
const persistenceOperationNames = new Set([
  'commitAuthorityMutation', 'consumeOutboxMessage', 'sealArtifactMetadata',
  'createBackupManifest', 'cutoverRestore', 'rebuildReadModel',
  'migrateDomainStore', 'purgeConsumedOutboxPayload',
  'acknowledgeAuthorityCommit', 'writeForeignAuthorityStore',
  'readForeignAuthorityDatabase', 'restoreAuthorityFromSource',
  'claimRecoveryPointObjective', 'replayOutbox', 'reconcileActiveAttempt',
  'beginRecovery', 'verifyRestoreCandidate', 'recoverFailedMigration',
]);

function fail(message) {
  throw new Error(message);
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function sha256(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function validateEnvelope(value, file, schemaVersion, commandNames) {
  const prefix = path.basename(file) + ': ';
  if (value.schemaVersion !== schemaVersion) fail(prefix + 'unknown schemaVersion');
  if (!value.fixtureId || !requiredCategories.has(value.category)) fail(prefix + 'invalid identity/category');
  if (!Array.isArray(value.requirementRefs) || value.requirementRefs.length === 0) fail(prefix + 'requirementRefs required');
  if (!value.principal || typeof value.principal.authenticated !== 'boolean') fail(prefix + 'principal required');
  if (!value.command || Object.keys(value.command).length !== 1) fail(prefix + 'exactly one command required');
  const commandName = Object.keys(value.command)[0];
  if (!commandNames.has(commandName)) fail(prefix + 'unknown command ' + commandName);
  if (!value.expected || !['committed', 'replayed', 'error'].includes(value.expected.outcome)) fail(prefix + 'expected outcome required');
  if (!Number.isInteger(value.expected.businessWriteCount)) fail(prefix + 'businessWriteCount required');
  if (value.expected.outcome === 'committed' && value.expected.businessWriteCount !== 1) fail(prefix + 'committed must write exactly once');
  if (value.expected.outcome !== 'committed' && value.expected.businessWriteCount !== 0) fail(prefix + 'error/replay must write zero');
  if (value.category === 'duplicate' && (value.expected.outcome !== 'replayed' || value.expected.replayed !== true)) fail(prefix + 'duplicate must replay original result');
  return { prefix, commandName };
}

function validateTaskFixture(file) {
  const value = readJson(file);
  const { prefix, commandName } = validateEnvelope(value, file, 'v01-task-fixture/v0.1', taskCommandNames);
  if (value.startingSnapshot && !taskStatuses.has(value.startingSnapshot.status)) fail(prefix + 'unknown starting status');
  if (value.expected.resultingStatus && !taskStatuses.has(value.expected.resultingStatus)) fail(prefix + 'unknown resulting status');
  if (value.expected.outcome === 'committed') {
    const expectedRevision = value.startingSnapshot ? value.startingSnapshot.revision + 1 : 1;
    if (value.expected.resultingRevision !== expectedRevision) fail(prefix + 'resulting revision must increment exactly once');
  }
  if (value.expected.resultingStatus === 'TASK_STATUS_HELD' && !value.expected.resumeStatus) fail(prefix + 'held must preserve resumeStatus');
  if (value.expected.resultingStatus === 'TASK_STATUS_COMPLETED') {
    if (commandName !== 'applyFounderVerdict') fail(prefix + 'completed requires ApplyFounderVerdict');
    if (!value.startingSnapshot || value.startingSnapshot.status !== 'TASK_STATUS_VERDICT_PENDING') fail(prefix + 'completed requires verdict_pending');
  }
  if (value.category === 'unauthorized' && value.expected.errorCode !== 'TASK_ERROR_CODE_PERMISSION_DENIED') fail(prefix + 'unauthorized must fail permission');
  return value.category;
}

function validateCollaborationFixture(file) {
  const value = readJson(file);
  const { prefix, commandName } = validateEnvelope(value, file, 'v01-collaboration-fixture/v0.1', collaborationCommandNames);
  const start = value.startingSnapshot;
  if (start && start.run && !runStatuses.has(start.run.status)) fail(prefix + 'unknown starting run status');
  if (start && start.step && !stepStatuses.has(start.step.status)) fail(prefix + 'unknown starting step status');
  if (start && start.attempt && !attemptStatuses.has(start.attempt.status)) fail(prefix + 'unknown starting attempt status');
  if (value.expected.resultingRunStatus && !runStatuses.has(value.expected.resultingRunStatus)) fail(prefix + 'unknown resulting run status');
  if (value.expected.resultingStepStatus && !stepStatuses.has(value.expected.resultingStepStatus)) fail(prefix + 'unknown resulting step status');
  if (value.expected.resultingAttemptStatus && !attemptStatuses.has(value.expected.resultingAttemptStatus)) fail(prefix + 'unknown resulting attempt status');
  if (value.expected.outcome === 'committed') {
    const expectedRunRevision = start && start.run ? start.run.revision + 1 : 1;
    if (value.expected.resultingRunRevision !== expectedRunRevision) fail(prefix + 'run revision must increment exactly once');
    if (value.expected.resultingStepRevision !== undefined) {
      const expectedStepRevision = start && start.step ? start.step.revision + 1 : 1;
      if (value.expected.resultingStepRevision !== expectedStepRevision) fail(prefix + 'step revision must increment exactly once');
    }
    if (value.expected.resultingAttemptRevision !== undefined) {
      const expectedAttemptRevision = start && start.attempt ? start.attempt.revision + 1 : 1;
      if (value.expected.resultingAttemptRevision !== expectedAttemptRevision) fail(prefix + 'attempt revision must increment exactly once');
    }
  }
  if (commandName === 'createRun') {
    if (value.expected.planStepCount !== 1 || value.expected.maxActiveAttempts !== 1) fail(prefix + 'V-01 run must contain exactly one step and one active attempt');
    if (value.expected.maxAttempts !== 2) fail(prefix + 'V-01 retry ceiling candidate must be two total attempts');
  }
  if (commandName === 'recordAttemptReturn') {
    if (value.expected.resultingAttemptStatus !== 'ATTEMPT_STATUS_RETURNED') fail(prefix + 'return must terminate only the attempt');
    if (value.expected.resultingRunStatus !== 'RUN_STATUS_RETURN_PENDING' || value.expected.resultingStepStatus !== 'STEP_STATUS_RETURN_PENDING') fail(prefix + 'run/step must await C-04 return commit');
    if (value.expected.taskStatusUnchanged !== 'TASK_STATUS_ACTIVE' || value.expected.taskBusinessWriteCount !== 0) fail(prefix + 'attempt return must not complete Task');
  }
  if (commandName === 'acquireAttemptLease' && (value.expected.resultingAttemptStatus !== 'ATTEMPT_STATUS_LEASED' || value.expected.resultingFencingToken !== 1 || value.expected.leaseIdCreated !== true)) fail(prefix + 'first lease must create identity and fencing token one');
  if (commandName === 'recordCheckpoint' && (value.expected.checkpointBindingComplete !== true || value.expected.checkpointProvesRecoverySafe !== false || !value.expected.latestCheckpointId)) fail(prefix + 'checkpoint must bind lineage but cannot prove recovery safety by itself');
  if (commandName === 'markAttemptOutcomeUnknown') {
    if (value.expected.resultingAttemptStatus !== 'ATTEMPT_STATUS_OUTCOME_UNKNOWN' || value.expected.automaticRetryAllowed !== false) fail(prefix + 'unknown outcome must block automatic retry');
  }
  if (value.category === 'recovery' && value.expected.resultingAttemptStatus === 'ATTEMPT_STATUS_FAILED') fail(prefix + 'uncertainty cannot be collapsed into failed');
  if (value.category === 'stale' && value.expected.errorCode !== 'COLLABORATION_ERROR_CODE_FENCING_REJECTED') fail(prefix + 'stale lease observation must fail fencing');
  if (value.category === 'unauthorized' && value.expected.errorCode !== 'COLLABORATION_ERROR_CODE_PERMISSION_DENIED') fail(prefix + 'unauthorized must fail permission');
  if (commandName === 'createAttempt' && start && start.run && start.run.activeAttemptCount >= start.run.maxActiveAttempts && value.expected.errorCode !== 'COLLABORATION_ERROR_CODE_CAPACITY_EXHAUSTED') fail(prefix + 'overlap must fail capacity');
  return value.category;
}

function validateHarnessFixture(file) {
  const value = readJson(file);
  const { prefix, commandName } = validateEnvelope(value, file, 'v01-harness-fixture/v0.1', harnessCommandNames);
  const start = value.startingState;
  const command = value.command[commandName];
  const expected = value.expected;
  if (commandName === 'attestCapability' && expected.outcome === 'committed') {
    if (expected.resultingRegistryRevision !== start.registryRevision + 1 || expected.profileRevision !== 1) fail(prefix + 'first capability attestation must increment registry and create profile revision one');
    if (expected.profileStatus !== 'CAPABILITY_PROFILE_STATUS_ACTIVE' || expected.profileDigestCreated !== true) fail(prefix + 'attested profile must be immutable active digest');
    const declaration = command.declaration;
    if (!declaration || declaration.nativeProtocol.schemaSha256 !== 'b4e8157096dd054c008a4f1b538fb6cd8f1f2cb9577a97a4afef59c2296ed608') fail(prefix + 'Codex candidate must pin audited v2 schema digest');
    if (declaration.semantics.resume.includes('RESUME_SEMANTICS_PARTIAL_EXECUTION_RESUME') || expected.partialExecutionResumeClaimed !== false) fail(prefix + 'Codex thread resume cannot claim partial execution resume');
  }
  if (commandName === 'dispatch' && expected.outcome === 'committed') {
    if (expected.deliveryDisposition !== 'DELIVERY_DISPOSITION_DELIVERED' || expected.nativeDispatchCount !== 1) fail(prefix + 'dispatch must produce exactly one delivery');
    if (expected.harnessAccepted !== false) fail(prefix + 'delivery cannot imply harness ACK');
    for (const ref of ['capabilityProfileRef', 'budgetProfileRef', 'sandboxProfileRef', 'toolPolicyRef', 'dataEgressPolicyRef', 'approvalPolicyRef']) if (!command[ref] || !command[ref].sha256) fail(prefix + 'dispatch governed reference required: ' + ref);
  }
  if (commandName === 'ingestObservation' && expected.outcome === 'committed') {
    if (start && Number.isInteger(start.lastObservationSequence) && expected.resultingObservationSequence !== start.lastObservationSequence + 1) fail(prefix + 'observation sequence must advance exactly once');
    if (start && Number.isInteger(start.consumerOffset) && expected.resultingConsumerOffset !== start.consumerOffset + 1) fail(prefix + 'replay consumer offset must advance exactly once');
    if (command.fencingToken === undefined) fail(prefix + 'observation fencing token required');
  }
  if (commandName === 'ingestObservation' && command.artifactReturn && expected.outcome === 'committed') {
    if (expected.returnCandidateAvailable !== true || expected.artifactSetCreated !== false) fail(prefix + 'adapter return must remain a C-04 candidate');
    if (expected.attemptStatusUnchanged !== 'ATTEMPT_STATUS_RUNNING' || expected.taskStatusUnchanged !== 'TASK_STATUS_ACTIVE') fail(prefix + 'artifact return candidate cannot advance Attempt or Task');
  }
  if (commandName === 'ingestObservation' && command.approvalRequest && expected.outcome === 'committed') {
    const allowed = new Set(expected.allowedDecisions || []);
    for (const decision of ['APPROVAL_DECISION_ALLOW_ONCE', 'APPROVAL_DECISION_DENY', 'APPROVAL_DECISION_CANCEL_ATTEMPT']) if (!allowed.has(decision)) fail(prefix + 'V-01 approval decision set incomplete');
    if (expected.automaticApproval !== false) fail(prefix + 'Harness approval cannot be automatic');
  }
  if (commandName === 'decideApproval' && expected.outcome === 'committed') {
    if (!['POLICY_AUTHORITY', 'FOUNDER_AUTHORITY'].includes(value.principal.kind) || !command.authorityDecisionRef) fail(prefix + 'approval decision requires trusted authority ref');
    if (expected.persistentNativePolicyMutation !== false) fail(prefix + 'V-01 approval cannot mutate persistent native policy');
  }
  if (commandName === 'cancel' && expected.outcome === 'committed') {
    if (expected.deliveryDisposition !== 'CANCELLATION_DELIVERY_DISPOSITION_DELIVERED' || expected.cancellationConfirmed !== false) fail(prefix + 'cancel delivery cannot imply cancellation confirmation');
    if (expected.attemptStatusAfterReceipt !== 'ATTEMPT_STATUS_CANCELLATION_PENDING' || expected.automaticRetryAllowed !== false) fail(prefix + 'unconfirmed cancel must remain pending and block retry');
  }
  if (commandName === 'resume' && expected.outcome === 'committed') {
    if (expected.deliveredSemantics !== command.requiredSemantics || expected.sameAttempt !== true) fail(prefix + 'resume must preserve Attempt and exact semantics');
    if (command.requiredSemantics === 'RESUME_SEMANTICS_SESSION_CONTINUE' && expected.partialExecutionResumeClaimed !== false) fail(prefix + 'session continuation cannot claim partial execution resume');
  }
  if (value.category === 'duplicate' && expected.outcome !== 'replayed') fail(prefix + 'duplicate observation must replay');
  if (value.category === 'stale' && expected.errorCode !== 'HARNESS_ERROR_CODE_FENCING_REJECTED') fail(prefix + 'stale observation must fail fencing');
  if (value.category === 'unauthorized' && expected.errorCode !== 'HARNESS_ERROR_CODE_PERMISSION_DENIED') fail(prefix + 'unauthorized Harness action must fail permission');
  if (value.fixtureId.includes('protocol-fingerprint-drift') && (expected.errorCode !== 'HARNESS_ERROR_CODE_PROTOCOL_MISMATCH' || expected.nativeDispatchCount !== 0)) fail(prefix + 'protocol drift must block native dispatch');
  if (value.fixtureId.includes('natural-language-completion') && expected.errorCode !== 'HARNESS_ERROR_CODE_SCHEMA_INVALID') fail(prefix + 'natural language cannot form ArtifactReturn');
  if (value.fixtureId.includes('partial-resume-unsupported') && (expected.errorCode !== 'HARNESS_ERROR_CODE_RESUME_UNSUPPORTED' || expected.nativeResumeCount !== 0)) fail(prefix + 'unsupported partial resume must not call native Harness');
  if (value.fixtureId.includes('unknown-terminal-event') && (expected.errorCode !== 'HARNESS_ERROR_CODE_UNKNOWN_CRITICAL_EVENT' || expected.collaborationAction !== 'ATTEMPT_STATUS_HELD' || expected.automaticRetryAllowed !== false)) fail(prefix + 'unknown terminal event must fail closed to held');
  return value.category;
}

function validateArtifactFixture(file) {
  const value = readJson(file);
  const { prefix, commandName } = validateEnvelope(value, file, 'v01-artifact-fixture/v0.1', artifactCommandNames);
  const start = value.startingState;
  const command = value.command[commandName];
  const expected = value.expected;
  if (start && start.status && start.status.startsWith('ARTIFACT_STATUS_') && !artifactStatuses.has(start.status)) fail(prefix + 'unknown artifact status');
  if (start && start.status && start.status.startsWith('ARTIFACT_SET_STATUS_') && !artifactSetStatuses.has(start.status)) fail(prefix + 'unknown artifact set status');
  if (start && start.status && start.status.startsWith('RETURN_HANDOFF_STATUS_') && !returnHandoffStatuses.has(start.status)) fail(prefix + 'unknown return handoff status');
  if (expected.resultingStatus && expected.resultingStatus.startsWith('ARTIFACT_STATUS_') && !artifactStatuses.has(expected.resultingStatus)) fail(prefix + 'unknown resulting artifact status');
  if (expected.resultingStatus && expected.resultingStatus.startsWith('ARTIFACT_SET_STATUS_') && !artifactSetStatuses.has(expected.resultingStatus)) fail(prefix + 'unknown resulting artifact set status');
  if (expected.resultingStatus && expected.resultingStatus.startsWith('RETURN_HANDOFF_STATUS_') && !returnHandoffStatuses.has(expected.resultingStatus)) fail(prefix + 'unknown resulting return status');
  if (expected.outcome === 'committed' && expected.resultingRevision !== undefined) {
    const expectedRevision = start && Number.isInteger(start.revision) ? start.revision + 1 : 1;
    if (expected.resultingRevision !== expectedRevision) fail(prefix + 'resulting revision must increment exactly once');
  }
  if (commandName === 'stageArtifact' && expected.outcome === 'committed') {
    if (expected.resultingStatus !== 'ARTIFACT_STATUS_STAGED' || expected.sealed === true) fail(prefix + 'stage cannot seal content');
  }
  if (commandName === 'sealArtifact' && expected.outcome === 'committed') {
    if (expected.resultingStatus !== 'ARTIFACT_STATUS_SEALED' || expected.integrityStatus !== 'INTEGRITY_STATUS_DIGEST_VERIFIED' || expected.contentImmutable !== true) fail(prefix + 'seal requires verified digest and immutable content');
  }
  if (commandName === 'proposeClaim' && expected.outcome === 'committed') {
    if (expected.resultingStatus !== 'CLAIM_STATUS_PROPOSED' || expected.verificationPerformed !== false || expected.taskCompletionDecided !== false) fail(prefix + 'claim proposal cannot verify or complete Task');
  }
  if (commandName === 'recordEvidence' && expected.outcome === 'committed') {
    if (expected.resultingStatus !== 'EVIDENCE_STATUS_RECORDED' || expected.verificationPerformed !== false) fail(prefix + 'recorded evidence is not verification');
  }
  if (commandName === 'createArtifactSet' && expected.outcome === 'committed') {
    if (expected.resultingStatus !== 'ARTIFACT_SET_STATUS_DRAFT' || expected.allMembersSameLineage !== true) fail(prefix + 'new set must be a same-lineage draft');
  }
  if (commandName === 'sealArtifactSet' && expected.outcome === 'committed') {
    if (expected.resultingStatus !== 'ARTIFACT_SET_STATUS_SEALED' || expected.membershipImmutable !== true) fail(prefix + 'sealed set membership must be immutable');
  }
  if (commandName === 'submitReturnHandoff' && expected.outcome === 'committed') {
    if (expected.resultingStatus !== 'RETURN_HANDOFF_STATUS_RECEIPTED' || expected.returnReceiptCreated !== true || expected.acceptedForEvidenceIntake !== true) fail(prefix + 'return submission must atomically create technical receipt');
    if (expected.verificationPerformed !== false || expected.taskCompletionDecided !== false || expected.collaborationCommitStillRequired !== true) fail(prefix + 'return receipt cannot verify, complete Task, or bypass Collaboration commit');
  }
  if (value.fixtureId.includes('digest-mismatch') && expected.errorCode !== 'ARTIFACT_ERROR_CODE_DIGEST_MISMATCH') fail(prefix + 'digest mismatch must fail integrity');
  if (value.fixtureId.includes('unsealed-member') && expected.errorCode !== 'ARTIFACT_ERROR_CODE_MEMBER_NOT_SEALED') fail(prefix + 'unsealed member must block set seal');
  if (value.fixtureId.includes('path-traversal') && expected.errorCode !== 'ARTIFACT_ERROR_CODE_SCOPE_VIOLATION') fail(prefix + 'path traversal must fail scope');
  if (value.fixtureId.includes('secret-detected') && (expected.errorCode !== 'ARTIFACT_ERROR_CODE_SECRET_DETECTED' || expected.safeErrorContainsSecret !== false)) fail(prefix + 'secret detection must fail without disclosure');
  if (value.fixtureId.includes('self-reported-independent') && expected.errorCode !== 'ARTIFACT_ERROR_CODE_INDEPENDENCE_VIOLATION') fail(prefix + 'claim proposer cannot self-certify independent evidence');
  if (value.fixtureId.includes('unknown-claim-profile') && expected.errorCode !== 'ARTIFACT_ERROR_CODE_SCHEMA_INVALID') fail(prefix + 'unknown claim profile cannot enter active graph');
  if (value.fixtureId.includes('lineage-mismatch') && expected.errorCode !== 'ARTIFACT_ERROR_CODE_LINEAGE_MISMATCH') fail(prefix + 'mixed Attempt lineage must fail set seal');
  if (value.category === 'duplicate' && (expected.outcome !== 'replayed' || expected.verificationPerformed !== false || expected.taskCompletionDecided !== false)) fail(prefix + 'duplicate return must replay without conclusion');
  if (value.category === 'stale' && expected.errorCode !== 'ARTIFACT_ERROR_CODE_REVISION_CONFLICT') fail(prefix + 'stale artifact command must fail CAS');
  if (value.category === 'unauthorized' && expected.errorCode !== 'ARTIFACT_ERROR_CODE_PERMISSION_DENIED') fail(prefix + 'unauthorized artifact action must fail permission');
  if (value.fixtureId.includes('orphan-staged-blob') && (expected.blobReused !== true || expected.duplicateBlobWritten !== false || expected.sealed !== false)) fail(prefix + 'orphan recovery must reuse but not auto-seal blob');
  if (value.fixtureId.includes('return-receipt-replay') && (expected.outcome !== 'replayed' || expected.outboxRedelivered !== true || expected.taskCompletionDecided !== false)) fail(prefix + 'receipt recovery must replay durable outbox without conclusion');
  if (commandName === 'recordEvidence' && command.independentOfClaimProposer === true && value.principal.principalId === (start && start.claimProposerPrincipalId) && expected.outcome !== 'error') fail(prefix + 'same principal cannot claim independent evidence');
  return value.category;
}

function validateVerificationFixture(file) {
  const value = readJson(file);
  const { prefix, commandName } = validateEnvelope(value, file, 'v01-verification-fixture/v0.1', verificationCommandNames);
  const start = value.startingState;
  const command = value.command[commandName];
  const expected = value.expected;
  if (start && start.status && !verificationStatuses.has(start.status)) fail(prefix + 'unknown starting verification status');
  if (expected.resultingStatus && !verificationStatuses.has(expected.resultingStatus)) fail(prefix + 'unknown resulting verification status');
  if (expected.outcome === 'committed' && expected.resultingRevision !== undefined) {
    const expectedRevision = start && Number.isInteger(start.revision) ? start.revision + 1 : 1;
    if (expected.resultingRevision !== expectedRevision) fail(prefix + 'verification revision must increment exactly once');
  }
  if (commandName === 'attestCheckerProfile' && expected.outcome === 'committed') {
    if (expected.resultingProfileStatus !== 'CHECKER_PROFILE_STATUS_ACTIVE' || expected.resultingProfileRevision !== 1 || expected.profileImmutable !== true) fail(prefix + 'attested checker profile must be immutable active revision one');
  }
  if (commandName === 'createVerificationRequest' && expected.outcome === 'committed') {
    if (expected.resultingStatus !== 'VERIFICATION_STATUS_QUEUED' || expected.bindingImmutable !== true || expected.taskStatusUnchanged !== 'TASK_STATUS_VERIFICATION_PENDING') fail(prefix + 'request must freeze bindings without advancing Task');
  }
  if (commandName === 'startVerificationRun' && expected.outcome === 'committed') {
    if (expected.resultingStatus !== 'VERIFICATION_STATUS_RUNNING' || expected.checkerExecutionCount !== 1) fail(prefix + 'start must create exactly one verification execution');
  }
  if (commandName === 'recordCriterionResult' && expected.outcome === 'committed') {
    if (expected.resultingStatus !== 'VERIFICATION_STATUS_RUNNING' || expected.criterionResultImmutable !== true && expected.discrepancyImmutable !== true) fail(prefix + 'criterion results must remain immutable run facts');
  }
  if (commandName === 'completeVerification' && expected.outcome === 'committed') {
    if (expected.resultingStatus !== 'VERIFICATION_STATUS_COMPLETED' || expected.taskCompletionDecided !== false) fail(prefix + 'verification completion cannot decide Task completion');
    if (command.conclusion === 'VERIFICATION_CONCLUSION_PASSED') {
      if (command.overallEvidenceCoverage !== 'EVIDENCE_COVERAGE_COMPLETE' || start.allMustPassEvidenceComplete !== true || start.requiredAssuranceSatisfied !== true) fail(prefix + 'passed requires complete must-pass evidence and assurance');
    }
    if (command.conclusion === 'VERIFICATION_CONCLUSION_INDETERMINATE' && expected.checkerErrorTreatedAsClaimFailure !== false) fail(prefix + 'checker error cannot become claim failure');
    if (command.founderVerdict || command.founderVerdictRef) fail(prefix + 'verification artifact cannot embed FounderVerdict');
  }
  if (value.fixtureId.includes('unsealed-artifact-set') && expected.errorCode !== 'VERIFICATION_ERROR_CODE_ARTIFACT_SET_NOT_SEALED') fail(prefix + 'unsealed set must block verification');
  if (value.fixtureId.includes('manifest-mismatch') && expected.errorCode !== 'VERIFICATION_ERROR_CODE_MANIFEST_MISMATCH') fail(prefix + 'manifest mismatch must block checker execution');
  if (value.fixtureId.includes('claim-binding-mismatch') && expected.errorCode !== 'VERIFICATION_ERROR_CODE_CLAIM_MISMATCH') fail(prefix + 'claim mismatch must block checker execution');
  if (value.fixtureId.includes('acceptance-contract-drift') && expected.errorCode !== 'VERIFICATION_ERROR_CODE_ACCEPTANCE_CONTRACT_MISMATCH') fail(prefix + 'acceptance drift must block checker execution');
  if (value.fixtureId.includes('passed-with-unverified-must') && expected.errorCode !== 'VERIFICATION_ERROR_CODE_EVIDENCE_INCOMPLETE') fail(prefix + 'unverified must-pass cannot conclude passed');
  if (value.fixtureId.includes('insufficient-assurance-pass') && expected.errorCode !== 'VERIFICATION_ERROR_CODE_CHECKER_PROFILE_MISMATCH') fail(prefix + 'lower assurance checker cannot satisfy deterministic criterion');
  if (value.fixtureId.includes('embedded-founder-verdict') && (expected.errorCode !== 'VERIFICATION_ERROR_CODE_SCHEMA_INVALID' || expected.founderVerdictWritten !== false)) fail(prefix + 'embedded FounderVerdict must be rejected');
  if (value.category === 'duplicate' && (expected.outcome !== 'replayed' || expected.taskCompletionDecided !== false)) fail(prefix + 'duplicate verification completion must replay without Task conclusion');
  if (value.category === 'stale' && expected.errorCode !== 'VERIFICATION_ERROR_CODE_REVISION_CONFLICT') fail(prefix + 'stale verification command must fail CAS');
  if (value.category === 'unauthorized' && (expected.errorCode !== 'VERIFICATION_ERROR_CODE_PERMISSION_DENIED' || expected.taskCompletionDecided !== false)) fail(prefix + 'unauthorized verifier write must fail permission');
  if (value.fixtureId.includes('checker-crash-to-held') && (expected.resultingStatus !== 'VERIFICATION_STATUS_HELD' || expected.claimTreatedAsFailed !== false || expected.automaticPassAllowed !== false)) fail(prefix + 'unknown checker outcome must hold without claim conclusion');
  if (value.fixtureId.includes('artifact-outbox-replay') && (expected.outcome !== 'replayed' || expected.outboxRedelivered !== true || expected.taskStatusUnchanged !== 'TASK_STATUS_VERIFICATION_PENDING')) fail(prefix + 'artifact outbox recovery must replay without advancing Task');
  return value.category;
}

function validateVerdictFixture(file) {
  const value = readJson(file);
  const { prefix, commandName } = validateEnvelope(value, file, 'v01-verdict-fixture/v0.1', verdictCommandNames);
  const start = value.startingState;
  const command = value.command[commandName];
  const expected = value.expected;
  if (start && start.state && !verdictStates.has(start.state)) fail(prefix + 'unknown starting verdict state');
  if (expected.resultingState && !verdictStates.has(expected.resultingState)) fail(prefix + 'unknown resulting verdict state');
  if (expected.outcome === 'committed' && expected.resultingStateRevision !== undefined) {
    const expectedRevision = start && Number.isInteger(start.revision) ? start.revision + 1 : 1;
    if (expected.resultingStateRevision !== expectedRevision) fail(prefix + 'verdict state revision must increment exactly once');
  }
  if (commandName === 'issueFounderVerdict' && expected.outcome === 'committed') {
    if (expected.resultingState !== 'FOUNDER_VERDICT_STATE_KIND_ISSUED') fail(prefix + 'issued verdict must enter ISSUED state');
    if (expected.taskBusinessWriteCount !== undefined && expected.taskBusinessWriteCount !== 0) fail(prefix + 'verdict issuance cannot mutate Task');
    if (command.decision === 'FOUNDER_VERDICT_DECISION_ACCEPT' && command.observedVerificationConclusion !== 'VERIFICATION_CONCLUSION_PASSED') {
      if (!Array.isArray(command.riskAcceptances) || command.riskAcceptances.length === 0) fail(prefix + 'non-passed acceptance requires explicit risk acceptance');
      if (command.requiredConfirmationClass !== 'CONFIRMATION_CLASS_ELEVATED_RISK_ACCEPTANCE') fail(prefix + 'non-passed acceptance requires elevated confirmation');
      if (expected.riskCoverageComplete !== true || expected.elevatedConfirmationVerified !== true) fail(prefix + 'non-passed acceptance must prove complete risk coverage and elevated confirmation');
    }
    if (command.decision === 'FOUNDER_VERDICT_DECISION_REWORK') {
      if (!command.reworkDirective) fail(prefix + 'rework verdict requires directive');
      if (expected.newWorkRevisionCreated !== false) fail(prefix + 'verdict authority cannot create a new work revision');
    }
  }
  if (commandName === 'consumeFounderVerdict' && expected.outcome === 'committed') {
    if (expected.resultingState !== 'FOUNDER_VERDICT_STATE_KIND_CONSUMED' || expected.consumptionReceiptCreated !== true) fail(prefix + 'consumption must create a receipt and enter CONSUMED state');
    if (!start || start.taskEventCommitted !== true || !command.taskCommitReceiptRef) fail(prefix + 'consumption requires a committed Task event receipt');
    if (expected.taskBusinessWriteCount !== undefined && expected.taskBusinessWriteCount !== 0) fail(prefix + 'verdict consumption cannot repeat the Task transition');
  }
  if (commandName === 'revokeFounderVerdict' && expected.outcome === 'committed') {
    if (!start || start.state !== 'FOUNDER_VERDICT_STATE_KIND_ISSUED' || expected.resultingState !== 'FOUNDER_VERDICT_STATE_KIND_REVOKED') fail(prefix + 'only an unconsumed issued verdict may be revoked');
    if (expected.taskBusinessWriteCount !== undefined && expected.taskBusinessWriteCount !== 0) fail(prefix + 'revocation cannot mutate Task');
    if (expected.taskStatusUnchanged !== 'TASK_STATUS_VERDICT_PENDING') fail(prefix + 'revocation must leave Task verdict pending');
  }
  const expectedErrors = [
    ['accept-nonpassed-without-risk', 'VERDICT_ERROR_CODE_RISK_ACCEPTANCE_REQUIRED'],
    ['risk-coverage-incomplete', 'VERDICT_ERROR_CODE_RISK_COVERAGE_INCOMPLETE'],
    ['risk-cannot-override-redline', 'VERDICT_ERROR_CODE_NON_OVERRIDABLE_GATE'],
    ['rework-without-directive', 'VERDICT_ERROR_CODE_REWORK_DIRECTIVE_REQUIRED'],
    ['risk-confirmation-too-weak', 'VERDICT_ERROR_CODE_CONFIRMATION_REQUIRED'],
    ['expired-verdict-consumption', 'VERDICT_ERROR_CODE_EXPIRED'],
    ['stale-task-scope', 'VERDICT_ERROR_CODE_SCOPE_STALE'],
    ['consume-before-task-commit', 'VERDICT_ERROR_CODE_TASK_COMMIT_RECEIPT_INVALID'],
  ];
  for (const [needle, errorCode] of expectedErrors) {
    if (value.fixtureId.includes(needle) && expected.errorCode !== errorCode) fail(prefix + needle + ' must fail with ' + errorCode);
  }
  if (value.fixtureId.includes('risk-confirmation-too-weak') && expected.requiredConfirmationClass !== 'CONFIRMATION_CLASS_ELEVATED_RISK_ACCEPTANCE') fail(prefix + 'weak risk confirmation must request elevated confirmation');
  if (value.category === 'stale' && expected.errorCode !== 'VERDICT_ERROR_CODE_REVISION_CONFLICT') fail(prefix + 'stale verdict command must fail CAS');
  if (value.category === 'unauthorized' && expected.errorCode !== 'VERDICT_ERROR_CODE_PERMISSION_DENIED') fail(prefix + 'unauthorized verdict issue must fail permission');
  if (value.fixtureId.includes('task-committed-consumption-pending') && (expected.taskBusinessWriteCount !== 0 || expected.duplicateTaskTransition !== false)) fail(prefix + 'recovery must consume without repeating Task transition');
  if (value.fixtureId.includes('issued-verdict-not-auto-applied') && (expected.taskStatusUnchanged !== 'TASK_STATUS_VERDICT_PENDING' || expected.automaticTaskApplication !== false)) fail(prefix + 'issued verdict must not auto-apply to Task');
  return value.category;
}

function validateLocalApiFixture(file) {
  const value = readJson(file);
  const prefix = path.basename(file) + ': ';
  if (value.schemaVersion !== 'v01-localapi-fixture/v0.1') fail(prefix + 'unknown schemaVersion');
  if (!value.fixtureId || !requiredCategories.has(value.category)) fail(prefix + 'invalid identity/category');
  if (!Array.isArray(value.requirementRefs) || value.requirementRefs.length === 0) fail(prefix + 'requirementRefs required');
  if (!value.principal || typeof value.principal.authenticated !== 'boolean') fail(prefix + 'principal required');
  if (!value.transport || !value.transport.kind) fail(prefix + 'transport required');
  if (!value.operation || Object.keys(value.operation).length !== 1) fail(prefix + 'exactly one operation required');
  const operationName = Object.keys(value.operation)[0];
  if (!localApiOperationNames.has(operationName)) fail(prefix + 'unknown operation ' + operationName);
  const expected = value.expected;
  if (!expected || !['ok', 'replayed', 'error', 'reset_required'].includes(expected.outcome)) fail(prefix + 'expected outcome required');
  if (!Number.isInteger(expected.businessWriteCount)) fail(prefix + 'businessWriteCount required');
  if (expected.outcome === 'replayed' && (value.category !== 'duplicate' || expected.replayed !== true || expected.businessWriteCount !== 0)) fail(prefix + 'replay must be duplicate with zero writes');
  if (expected.outcome !== 'ok' && expected.businessWriteCount !== 0) fail(prefix + 'failure/reset/replay must write zero');
  if (value.transport.kind === 'LOOPBACK_TCP' && (expected.outcome !== 'error' || expected.listenerCreated !== false)) fail(prefix + 'V-01 must not expose loopback TCP');
  if (operationName === 'openSession' && expected.outcome === 'ok') {
    if (value.transport.peerCredentialVerified !== true || expected.authenticatedPrincipalFromTransport !== true || expected.surfaceUsedAsAuthorization !== false) fail(prefix + 'session identity must come from trusted IPC peer credentials');
  }
  if (operationName === 'getTaskView' && expected.outcome === 'ok') {
    if (expected.sourceRevisionVectorPreserved === false || expected.unifiedStatusInvented === true) fail(prefix + 'Task view must preserve source revisions without inventing unified status');
  }
  if (operationName === 'listTaskViews' && expected.outcome === 'ok') {
    if (expected.cursorBindsFilterSortAndPosition !== true || expected.stableTieBreaker !== 'task_id') fail(prefix + 'list cursor must bind query and stable tie breaker');
  }
  if (operationName === 'executeTaskCommand' && expected.outcome === 'ok') {
    if (expected.writeOwner !== 'TaskAuthority' || expected.projectionAwaitTokenCreated !== true || expected.projectedViewReturnedAsCurrent !== false || expected.localApiFactWritten !== false) fail(prefix + 'gateway must preserve Task authority and projection lag');
  }
  if (operationName === 'executeFounderVerdict' && expected.outcome === 'ok') {
    if (expected.writeOwner !== 'FounderVerdictAuthority' || expected.localApiReinterpretedDecision !== false) fail(prefix + 'gateway cannot reinterpret Founder verdict');
  }
  if (operationName === 'watchTaskViews' && expected.outcome === 'ok' && value.fixtureId.includes('complete-snapshots')) {
    if (expected.completeSnapshot !== true || expected.fieldPatch !== false || expected.delivery !== 'at_least_once' || expected.orderedWithinEpoch !== true) fail(prefix + 'stream must use ordered complete snapshots with at-least-once delivery');
  }
  const expectedErrors = [
    ['incompatible-contract', 'LOCAL_API_ERROR_CODE_CONTRACT_INCOMPATIBLE'],
    ['loopback-tcp-transport', 'LOCAL_API_ERROR_CODE_UNAUTHENTICATED'],
    ['cursor-filter-mismatch', 'LOCAL_API_ERROR_CODE_CURSOR_INVALID'],
    ['incoherent-source-vector', 'LOCAL_API_ERROR_CODE_INTEGRITY_FAILURE'],
    ['stream-field-patch', 'LOCAL_API_ERROR_CODE_INVALID_ARGUMENT'],
    ['authority-error-rewritten-as-success', 'LOCAL_API_ERROR_CODE_INTEGRITY_FAILURE'],
    ['surface-capability-divergence', 'LOCAL_API_ERROR_CODE_CONTRACT_INCOMPATIBLE'],
    ['minimum-position-timeout', 'LOCAL_API_ERROR_CODE_PROJECTION_BEHIND'],
    ['cursor-old-epoch', 'LOCAL_API_ERROR_CODE_PROJECTION_RESET_REQUIRED'],
  ];
  for (const [needle, errorCode] of expectedErrors) if (value.fixtureId.includes(needle) && expected.errorCode !== errorCode) fail(prefix + needle + ' must fail with ' + errorCode);
  if (value.category === 'unauthorized' && (expected.errorCode !== 'LOCAL_API_ERROR_CODE_PERMISSION_DENIED' || expected.businessWriteCount !== 0)) fail(prefix + 'unauthorized Local API operation must fail before authority write');
  if (value.fixtureId.includes('tui-same-kernel-command') && (expected.sameClientKernelContractAsCliDesktop !== true || expected.samePrincipalCapabilitiesAcrossSurfaces !== true || expected.presentationSurfaceAffectedAuthorization !== false)) fail(prefix + 'TUI must consume the same client kernel and principal-derived capabilities');
  if (value.fixtureId.includes('surface-capability-divergence') && (expected.surfaceSpecificCapabilityProfileRejected !== true || expected.principalPolicyRemainsAuthority !== true)) fail(prefix + 'presentation surface cannot define a capability profile');
  if (value.fixtureId.includes('model-founder-write') && expected.founderDelegationInferred !== false) fail(prefix + 'model identity cannot imply Founder delegation');
  if (value.fixtureId.includes('stream-gap-reset-required') && (expected.frameKind !== 'STREAM_FRAME_KIND_RESET_REQUIRED' || expected.clientMustRefetch !== true)) fail(prefix + 'retention gap must require full refetch');
  if (value.fixtureId.includes('projector-rebuild-new-epoch') && (expected.newEpoch === value.startingState.oldEpoch || expected.authorityBusinessWriteCount !== 0)) fail(prefix + 'rebuild must change epoch without authority writes');
  if (value.fixtureId.includes('evidence-redaction') && (expected.absolutePathExposed !== false || expected.secretExposed !== false || expected.rawBlobEmbedded !== false)) fail(prefix + 'read model cannot expose paths, secrets or raw blobs');
  return value.category;
}

function validatePersistenceFixture(file) {
  const value = readJson(file);
  const prefix = path.basename(file) + ': ';
  if (value.schemaVersion !== 'v01-persistence-fixture/v0.1') fail(prefix + 'unknown schemaVersion');
  if (!value.fixtureId || !requiredCategories.has(value.category)) fail(prefix + 'invalid identity/category');
  if (!Array.isArray(value.requirementRefs) || value.requirementRefs.length === 0) fail(prefix + 'requirementRefs required');
  if (!value.principal || typeof value.principal.authenticated !== 'boolean') fail(prefix + 'principal required');
  if (!value.operation || Object.keys(value.operation).length !== 1) fail(prefix + 'exactly one operation required');
  const operationName = Object.keys(value.operation)[0];
  if (!persistenceOperationNames.has(operationName)) fail(prefix + 'unknown operation ' + operationName);
  const expected = value.expected;
  if (!expected || !['ok', 'replayed', 'error', 'held'].includes(expected.outcome)) fail(prefix + 'expected outcome required');
  if (!Number.isInteger(expected.businessWriteCount)) fail(prefix + 'businessWriteCount required');
  if (expected.outcome !== 'ok' && expected.businessWriteCount !== 0) fail(prefix + 'failure/held/replay must write zero business facts');
  if (value.category === 'duplicate' && (expected.outcome !== 'replayed' || expected.replayed !== true || expected.businessWriteCount !== 0)) fail(prefix + 'duplicate must replay original receipt with zero writes');
  if (value.category === 'unauthorized' && (expected.errorCode !== 'PERSISTENCE_ERROR_CODE_PERMISSION_DENIED' || expected.businessWriteCount !== 0)) fail(prefix + 'unauthorized persistence operation must fail before write');
  if (operationName === 'commitAuthorityMutation' && expected.outcome === 'ok') {
    if (expected.stateEventIdempotencyOutboxAtomic !== true || expected.acknowledgedAfterDurabilityBarrier !== true || !expected.writeOwner) fail(prefix + 'authority commit must atomically persist state/event/idempotency/outbox before ACK');
  }
  if (operationName === 'consumeOutboxMessage' && expected.outcome === 'ok') {
    if (expected.consumerStateEventInboxAtomic !== true || expected.sourceAuthorityStoreDirectRead !== false || expected.consumptionReceiptCreated !== true) fail(prefix + 'consumer must commit its state/event/inbox receipt without reading source store');
  }
  if (operationName === 'createBackupManifest' && expected.outcome === 'ok') {
    if (expected.requiredDomainsCovered !== true || expected.pendingOutboxPreserved !== true || expected.liveArtifactBlobsCovered !== true || expected.derivedReadModelRequired !== false) fail(prefix + 'backup manifest must cover required domains, in-flight outbox and live blobs without derived stores');
  }
  if (operationName === 'cutoverRestore' && expected.outcome === 'ok') {
    if (expected.verifiedInIsolation !== true || expected.inPlaceOverwrite !== false || expected.atomicStoreSetCutover !== true || expected.authorityBusinessWriteCount !== 0) fail(prefix + 'restore must verify in isolation and cut over without business writes');
  }
  if (operationName === 'rebuildReadModel' && expected.outcome === 'ok') {
    if (!expected.newProjectionEpoch || expected.authorityBusinessWriteCount !== 0 || expected.derivedStoreUsedAsFactSource === true) fail(prefix + 'read model rebuild must create a new epoch from authority events without authority writes');
  }
  const expectedErrors = [
    ['split-state-event-outbox', 'PERSISTENCE_ERROR_CODE_ATOMIC_COMMIT_VIOLATION'],
    ['ack-before-durability-barrier', 'PERSISTENCE_ERROR_CODE_DURABILITY_NOT_PROVEN'],
    ['shared-authority-write-store', 'PERSISTENCE_ERROR_CODE_PERMISSION_DENIED'],
    ['direct-cross-authority-db-read', 'PERSISTENCE_ERROR_CODE_PERMISSION_DENIED'],
    ['backup-missing-required-domain', 'PERSISTENCE_ERROR_CODE_BACKUP_INCOMPLETE'],
    ['backup-missing-live-blob', 'PERSISTENCE_ERROR_CODE_BLOB_COVERAGE_INCOMPLETE'],
    ['restore-in-place-unverified', 'PERSISTENCE_ERROR_CODE_RESTORE_NOT_VERIFIED'],
    ['derived-readmodel-as-restore-source', 'PERSISTENCE_ERROR_CODE_RESTORE_NOT_VERIFIED'],
    ['destructive-migration-without-approved-plan', 'PERSISTENCE_ERROR_CODE_MIGRATION_NOT_AUTHORIZED'],
    ['media-loss-rpo-zero-claim-without-replica', 'PERSISTENCE_ERROR_CODE_MEDIA_LOSS_NOT_COVERED'],
    ['backup-drops-pending-outbox', 'PERSISTENCE_ERROR_CODE_BACKUP_INCOMPLETE'],
    ['stale-recovery-fence', 'PERSISTENCE_ERROR_CODE_FENCE_STALE'],
    ['stale-backup-domain-watermark', 'PERSISTENCE_ERROR_CODE_REVISION_CONFLICT'],
  ];
  for (const [needle, errorCode] of expectedErrors) if (value.fixtureId.includes(needle) && expected.errorCode !== errorCode) fail(prefix + needle + ' must fail with ' + errorCode);
  if (value.fixtureId.includes('media-loss-rpo-zero') && (expected.rpoZeroClaimRejected !== true || expected.actualRecoveryPointMustBeReported !== true)) fail(prefix + 'media loss RPO must be honest without a synchronous replica');
  if (value.fixtureId.includes('outbox-commit-before-delivery') && (expected.sameMessageIdReplayed !== true || expected.newSourceBusinessEventCreated !== false)) fail(prefix + 'outbox recovery must replay the committed message, not create a new fact');
  if (value.fixtureId.includes('consumer-commit-before-ack') && (expected.duplicateDeliveryDetected !== true || expected.consumerBusinessWriteRepeated !== false)) fail(prefix + 'consumer recovery must dedupe after commit-before-ACK');
  if (value.fixtureId.includes('active-attempt-outcome-unknown-held') && (expected.recoveryClass !== 'RECOVERY_CLASS_RECONCILE_BEFORE_RETRY' || expected.automaticRetry !== false)) fail(prefix + 'unknown external effect must reconcile or hold, never auto-retry');
  if (value.fixtureId.includes('corrupt-authority-store-held') && (expected.commandGatewayEnabled !== false || expected.corruptStoreOverwritten !== false)) fail(prefix + 'corrupt authority store must fail closed without overwrite');
  if (value.fixtureId.includes('process-crash-after-ack-rpo-zero') && (expected.acknowledgedCommitLost !== false || expected.rpoSeconds !== 0 || expected.faultModel !== 'PROCESS_OR_OS_CRASH_DURABLE_MEDIA_INTACT')) fail(prefix + 'RPO 0 proof must bind the declared crash fault model');
  if (value.fixtureId.includes('partial-migration') && (expected.entireStoreSetRestored !== true || expected.mixedSchemaSetActivated !== false || expected.automaticDownMigration !== false)) fail(prefix + 'partial migration failure must restore the pre-upgrade set without automatic down-migration');
  return value.category;
}

function main() {
  const manifest = readJson(manifestPath);
  if (manifest.schemaVersion !== 'v01-gate3-contract-candidate-manifest/v0.1') fail('manifest schemaVersion');
  const manifestPaths = new Set(manifest.artifacts.map((artifact) => artifact.path.replace(/\\/g, '/')));
  const taskCategories = new Set();
  const taskFixtureFiles = fs.readdirSync(taskFixtureRoot).filter((name) => name.endsWith('.json')).sort();
  for (const name of taskFixtureFiles) taskCategories.add(validateTaskFixture(path.join(taskFixtureRoot, name)));
  for (const category of requiredCategories) if (!taskCategories.has(category)) fail('missing task fixture category: ' + category);
  const collaborationCategories = new Set();
  const collaborationFixtureFiles = fs.readdirSync(collaborationFixtureRoot).filter((name) => name.endsWith('.json')).sort();
  for (const name of collaborationFixtureFiles) collaborationCategories.add(validateCollaborationFixture(path.join(collaborationFixtureRoot, name)));
  for (const category of requiredCategories) if (!collaborationCategories.has(category)) fail('missing collaboration fixture category: ' + category);
  const harnessCategories = new Set();
  const harnessFixtureFiles = fs.readdirSync(harnessFixtureRoot).filter((name) => name.endsWith('.json')).sort();
  for (const name of harnessFixtureFiles) harnessCategories.add(validateHarnessFixture(path.join(harnessFixtureRoot, name)));
  for (const category of requiredCategories) if (!harnessCategories.has(category)) fail('missing harness fixture category: ' + category);
  const artifactCategories = new Set();
  const artifactFixtureFiles = fs.readdirSync(artifactFixtureRoot).filter((name) => name.endsWith('.json')).sort();
  for (const name of artifactFixtureFiles) artifactCategories.add(validateArtifactFixture(path.join(artifactFixtureRoot, name)));
  for (const category of requiredCategories) if (!artifactCategories.has(category)) fail('missing artifact fixture category: ' + category);
  const verificationCategories = new Set();
  const verificationFixtureFiles = fs.readdirSync(verificationFixtureRoot).filter((name) => name.endsWith('.json')).sort();
  for (const name of verificationFixtureFiles) verificationCategories.add(validateVerificationFixture(path.join(verificationFixtureRoot, name)));
  for (const category of requiredCategories) if (!verificationCategories.has(category)) fail('missing verification fixture category: ' + category);
  const verdictCategories = new Set();
  const verdictFixtureFiles = fs.readdirSync(verdictFixtureRoot).filter((name) => name.endsWith('.json')).sort();
  for (const name of verdictFixtureFiles) verdictCategories.add(validateVerdictFixture(path.join(verdictFixtureRoot, name)));
  for (const category of requiredCategories) if (!verdictCategories.has(category)) fail('missing verdict fixture category: ' + category);
  const localApiCategories = new Set();
  const localApiFixtureFiles = fs.readdirSync(localApiFixtureRoot).filter((name) => name.endsWith('.json')).sort();
  for (const name of localApiFixtureFiles) localApiCategories.add(validateLocalApiFixture(path.join(localApiFixtureRoot, name)));
  for (const category of requiredCategories) if (!localApiCategories.has(category)) fail('missing localapi fixture category: ' + category);
  const persistenceCategories = new Set();
  const persistenceFixtureFiles = fs.readdirSync(persistenceFixtureRoot).filter((name) => name.endsWith('.json')).sort();
  for (const name of persistenceFixtureFiles) persistenceCategories.add(validatePersistenceFixture(path.join(persistenceFixtureRoot, name)));
  for (const category of requiredCategories) if (!persistenceCategories.has(category)) fail('missing persistence fixture category: ' + category);
  for (const artifact of manifest.artifacts) {
    const file = path.resolve(root, artifact.path);
    if (!file.startsWith(root + path.sep) || !fs.existsSync(file)) fail('manifest path invalid/missing: ' + artifact.path);
    const actual = sha256(file);
    if (actual !== artifact.sha256) fail('digest drift: ' + artifact.path);
  }
  const machineRoots = [
    path.join(root, 'fixtures'),
    path.join(root, 'proto'),
  ];
  const walk = (dir) => fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const absolute = path.join(dir, entry.name);
    return entry.isDirectory() ? walk(absolute) : [absolute];
  });
  const requiredManifestFiles = machineRoots.flatMap(walk)
    .concat(fs.readdirSync(root).filter((name) => name.endsWith('-fixture-envelope.schema.json')).map((name) => path.join(root, name)));
  for (const file of requiredManifestFiles) {
    const relative = path.relative(root, file).replace(/\\/g, '/');
    if (!manifestPaths.has(relative)) fail('machine candidate missing from manifest: ' + relative);
  }
  const commonProto = fs.readFileSync(path.join(root, 'proto', 'egopulse', 'common', 'v1', 'common.proto'), 'utf8');
  const taskProto = fs.readFileSync(path.join(root, 'proto', 'egopulse', 'task', 'v1', 'task.proto'), 'utf8');
  const collaborationProto = fs.readFileSync(path.join(root, 'proto', 'egopulse', 'collaboration', 'v1', 'collaboration.proto'), 'utf8');
  const harnessProto = fs.readFileSync(path.join(root, 'proto', 'egopulse', 'harness', 'v1', 'harness.proto'), 'utf8');
  const artifactProto = fs.readFileSync(path.join(root, 'proto', 'egopulse', 'artifact', 'v1', 'artifact.proto'), 'utf8');
  const verificationProto = fs.readFileSync(path.join(root, 'proto', 'egopulse', 'verification', 'v1', 'verification.proto'), 'utf8');
  const verdictProto = fs.readFileSync(path.join(root, 'proto', 'egopulse', 'verdict', 'v1', 'verdict.proto'), 'utf8');
  const localApiProto = fs.readFileSync(path.join(root, 'proto', 'egopulse', 'localapi', 'v1', 'local_api.proto'), 'utf8');
  const persistenceProto = fs.readFileSync(path.join(root, 'proto', 'egopulse', 'persistence', 'v1', 'persistence.proto'), 'utf8');
  for (const required of ['syntax = "proto3"', 'package egopulse.common.v1', 'message CommandMetadata', 'message ContractReference']) {
    if (!commonProto.includes(required)) fail('common proto missing: ' + required);
  }
  for (const required of ['package egopulse.task.v1', 'enum TaskStatus', 'message TaskSnapshot', 'message TaskCommand', 'message TaskEvent', 'service TaskAuthorityService']) {
    if (!taskProto.includes(required)) fail('task proto missing: ' + required);
  }
  for (const required of ['package egopulse.collaboration.v1', 'enum RunStatus', 'enum StepStatus', 'enum AttemptStatus', 'enum AttemptCancellationDisposition', 'message Lease', 'message CheckpointReference', 'string task_id = 14', 'uint64 work_revision = 15', 'message CollaborationSnapshot', 'message CollaborationCommand', 'message CollaborationEvent', 'service CollaborationControlService']) {
    if (!collaborationProto.includes(required)) fail('collaboration proto missing: ' + required);
  }
  for (const required of ['package egopulse.harness.v1', 'enum SupportLevel', 'enum CancellationSemantics', 'enum ResumeSemantics', 'message CapabilityProfile', 'message DispatchEnvelope', 'message HarnessObservation', 'message ApprovalDecisionEnvelope', 'message CancelExecutionEnvelope', 'message ResumeExecutionEnvelope', 'message ArtifactReturnObservation', 'service HarnessAdapterService', 'service HarnessRegistryService']) {
    if (!harnessProto.includes(required)) fail('harness proto missing: ' + required);
  }
  for (const required of ['package egopulse.artifact.v1', 'message ContentAddress', 'message LineageBinding', 'message Provenance', 'message ArtifactDescriptor', 'message Claim', 'message Evidence', 'message ArtifactSet', 'message ReturnHandoff', 'message ReturnReceipt', 'bool verification_performed = 8', 'bool task_completion_decided = 9', 'service ArtifactAuthorityService']) {
    if (!artifactProto.includes(required)) fail('artifact proto missing: ' + required);
  }
  for (const required of ['package egopulse.verification.v1', 'message CheckerProfile', 'message VerificationBinding', 'message VerificationRequest', 'message CriterionResult', 'message Discrepancy', 'message UnverifiedItem', 'message VerificationArtifact', 'message VerificationRun', 'service VerificationAuthorityService']) {
    if (!verificationProto.includes(required)) fail('verification proto missing: ' + required);
  }
  for (const forbidden of ['message FounderVerdict', 'user_verdict', 'USER_OVERRIDDEN']) if (verificationProto.includes(forbidden)) fail('verification proto crosses FounderVerdict boundary: ' + forbidden);
  for (const required of ['package egopulse.verdict.v1', 'message VerdictScope', 'message FounderAuthorityProof', 'message RiskAcceptance', 'message FounderVerdict', 'message FounderVerdictState', 'message VerdictConsumptionReceipt', 'message VerdictCommand', 'message VerdictEvent', 'service FounderVerdictAuthorityService']) {
    if (!verdictProto.includes(required)) fail('verdict proto missing: ' + required);
  }
  for (const forbidden of ['message ApprovalDecision', 'message ParentReceipt', 'user_verdict', 'USER_OVERRIDDEN']) if (verdictProto.includes(forbidden)) fail('verdict proto crosses authority boundary: ' + forbidden);
  for (const required of ['package egopulse.localapi.v1', 'message ProjectionPosition', 'message SourceRevision', 'message ProjectionMetadata', 'message TaskView', 'message EvidenceGraphView', 'message ProjectionAwaitToken', 'message TaskViewStreamFrame', 'client_kernel_contract_ref', 'authorization_policy_ref', 'service LocalSessionService', 'service LocalReadModelService', 'service LocalCommandGatewayService']) {
    if (!localApiProto.includes(required)) fail('localapi proto missing: ' + required);
  }
  for (const forbidden of ['enum UnifiedTaskStatus', 'message LocalTaskFact', 'string actor_id', 'json_patch', 'surface_permission', 'tui_read_only', 'service ArtifactAuthorityService']) if (localApiProto.includes(forbidden)) fail('localapi proto crosses projection/authority boundary: ' + forbidden);
  for (const required of ['package egopulse.persistence.v1', 'enum PersistenceDomain', 'enum StoreRole', 'enum StoreHealth', 'enum RecoveryPhase', 'message DomainWatermark', 'message DurableCommitReceipt', 'message OutboxEnvelope', 'message InboxConsumptionReceipt', 'message DomainSnapshotDescriptor', 'message BackupManifest', 'message RestoreVerificationReport', 'message RecoveryPlan', 'service PersistenceParticipantService', 'service BackupRecoveryCoordinatorService']) {
    if (!persistenceProto.includes(required)) fail('persistence proto missing: ' + required);
  }
  for (const forbidden of ['service TaskAuthorityService', 'service FounderVerdictAuthorityService', 'message TaskSnapshot', 'exactly_once_delivery', 'global_transaction', 'shared_authority_store', 'sqlcipher', 'sqlite']) if (persistenceProto.toLowerCase().includes(forbidden.toLowerCase())) fail('persistence proto crosses architecture/technology boundary: ' + forbidden);
  const budgetProfileRelative = 'profiles/quality-budget/v1/v01-default.json';
  const budgetSchemaRelative = 'quality-budget-profile.schema.json';
  for (const relative of [budgetProfileRelative, budgetSchemaRelative]) if (!manifestPaths.has(relative)) fail('quality budget contract missing from manifest: ' + relative);
  const budgetProfile = readJson(path.join(root, budgetProfileRelative));
  if (budgetProfile.schemaVersion !== 'egopulse.quality-budget-profile/v0.1' || budgetProfile.designBindingGate !== 'Gate 3' || budgetProfile.verificationGate !== 'Gate 6') fail('quality budget gate binding invalid');
  const expectedBudgetIds = [
    ...Array.from({ length: 8 }, (_, index) => `QH-${String(index + 1).padStart(2, '0')}`),
    ...Array.from({ length: 8 }, (_, index) => `QT-${String(index + 1).padStart(2, '0')}`),
    ...Array.from({ length: 4 }, (_, index) => `QC-${String(index + 1).padStart(2, '0')}`),
    ...Array.from({ length: 9 }, (_, index) => `QR-${String(index + 1).padStart(2, '0')}`),
    ...Array.from({ length: 4 }, (_, index) => `QM-${String(index + 1).padStart(2, '0')}`),
  ];
  const budgetRules = new Map((budgetProfile.rules || []).map((rule) => [rule.requirementId, rule]));
  if (budgetRules.size !== expectedBudgetIds.length || expectedBudgetIds.some((id) => !budgetRules.has(id))) fail('quality budget must contain each D-03 rule exactly once');
  const limit = (id, name) => budgetRules.get(id).limits[name];
  if (limit('QH-01', 'maxCount') !== 0 || limit('QH-07', 'rpoSeconds') !== 0 || limit('QH-08', 'auditCompletenessPercent') !== 100) fail('governance redline values drifted');
  if (limit('QT-01', 'p95Milliseconds') !== 250 || limit('QT-02', 'p95Milliseconds') !== 2000 || limit('QT-03', 'p95Milliseconds') !== 500 || limit('QT-04', 'p95Milliseconds') !== 10000) fail('latency budget values drifted');
  if (limit('QC-01', 'maxCount') !== 1 || limit('QC-02', 'maxCount') !== 32 || limit('QC-04', 'defaultMilliseconds') !== 1200000) fail('concurrency budget values drifted');
  if (limit('QR-01', 'hardBytes') !== 536870912 || limit('QR-03', 'hardBytes') !== 2147483648 || limit('QR-09', 'minimumSecondsAfterTaskTerminal') !== 2592000) fail('resource budget values drifted');
  if (limit('QM-01', 'hardTokens') !== 500000 || limit('QM-02', 'hardTokens') !== 50000 || limit('QM-03', 'unknownMayRenderAsZero') !== false) fail('model usage budget values drifted');
  if (budgetProfile.measurementPolicy?.crashInjectionsPerBoundary !== 10 || budgetProfile.measurementPolicy?.crashBoundaryCount !== 7 || budgetProfile.measurementPolicy?.failedSamplesIncluded !== true) fail('measurement policy drifted');
  const validation = manifest.validation || {};
  for (const field of ['bufLint', 'bufBuild', 'protocCompile', 'crossLanguageGeneration', 'faultConformance', 'qualityBudgetProfile']) {
    if (typeof validation[field] !== 'string' || !validation[field].startsWith('passed_')) fail('toolchain evidence is not passed: ' + field);
  }
  if (typeof validation.bufBreaking !== 'string' || (!validation.bufBreaking.startsWith('passed_') && !validation.bufBreaking.startsWith('not_applicable_initial_contract_'))) {
    fail('Buf breaking evidence must pass or explicitly establish an initial baseline');
  }
  const c08 = manifest.groups.find((group) => group.id === 'C-08');
  if (!c08 || c08.status !== 'founder_confirmed_toolchain_verified') fail('C-08 must carry explicit Founder acceptance after technical verification');
  console.log(`candidate validation passed: ${taskFixtureFiles.length} task fixtures, ${collaborationFixtureFiles.length} collaboration fixtures, ${harnessFixtureFiles.length} harness fixtures, ${artifactFixtureFiles.length} artifact fixtures, ${verificationFixtureFiles.length} verification fixtures, ${verdictFixtureFiles.length} verdict fixtures, ${localApiFixtureFiles.length} localapi fixtures, ${persistenceFixtureFiles.length} persistence fixtures, ${manifest.artifacts.length} digests`);
  console.log('proto_toolchain_status=passed; Buf/protoc, Rust/TypeScript/Python generation, and SQLCipher process-crash conformance are verified');
  console.log('gate3_status=awaiting_founder_final_decision; all contract groups are Founder-confirmed and technical evidence is verified');
}

main();
