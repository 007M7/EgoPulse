#![forbid(unsafe_code)]

use serde::Serialize;
use thiserror::Error;

/// The smallest user-facing input accepted by the Director preview.
///
/// This is intentionally not a Task command. A preview must be produced before
/// the governance plane is allowed to create or dispatch a Task.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectorInput {
    pub intent: String,
    pub scope_ref: String,
    pub work_type: String,
    pub context_sources: Vec<ContextSourceInput>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextSourceInput {
    pub source_ref: String,
    pub label: String,
    pub authority: ContextAuthority,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContextAuthority {
    Founder,
    Project,
    Runtime,
    External,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WorkRequest {
    pub intent: String,
    pub scope_ref: String,
    pub work_type: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ContextSource {
    pub source_ref: String,
    pub label: String,
    pub authority: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ContextNotice {
    pub code: String,
    pub detail: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TokenBudget {
    pub planning_limit: u32,
    pub execution_limit: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ContextPack {
    pub included_sources: Vec<ContextSource>,
    pub excluded_sources: Vec<ContextNotice>,
    pub required_reads: Vec<String>,
    pub stale_context_warnings: Vec<String>,
    pub not_doing: Vec<String>,
    pub confidence: String,
    pub token_budget: TokenBudget,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GateResult {
    pub ready: bool,
    pub blockers: Vec<ContextNotice>,
    pub warnings: Vec<ContextNotice>,
    pub required_confirmations: Vec<String>,
    pub evidence_required: Vec<String>,
    pub cost_gate_required: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EventPacketPreview {
    pub work_request: WorkRequest,
    pub context_pack: ContextPack,
    pub gate_result: GateResult,
    pub route: String,
    pub return_format: String,
    pub ready_for_founder_confirmation: bool,
    pub dispatchable: bool,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum DirectorInputError {
    #[error("intent must not be empty")]
    EmptyIntent,
    #[error("scope reference must not be empty")]
    EmptyScope,
    #[error("work type must not be empty")]
    EmptyWorkType,
}

/// Normalize only the user-provided fields. It does not infer authority,
/// choose a provider, create a Task, or write Memory.
pub fn normalize_intent(input: &DirectorInput) -> Result<WorkRequest, DirectorInputError> {
    let intent = input.intent.trim();
    if intent.is_empty() {
        return Err(DirectorInputError::EmptyIntent);
    }
    let scope_ref = input.scope_ref.trim();
    if scope_ref.is_empty() {
        return Err(DirectorInputError::EmptyScope);
    }
    let work_type = input.work_type.trim();
    if work_type.is_empty() {
        return Err(DirectorInputError::EmptyWorkType);
    }
    Ok(WorkRequest {
        intent: intent.to_owned(),
        scope_ref: scope_ref.to_owned(),
        work_type: work_type.to_owned(),
    })
}

/// Compile the explicitly supplied source references into a read-only context
/// pack. This stage deliberately does not search, infer, persist, or select a
/// provider. The caller may render the pack before a Start Gate is evaluated.
pub fn build_context_pack(input: &DirectorInput) -> ContextPack {
    let included_sources: Vec<ContextSource> = input
        .context_sources
        .iter()
        .filter(|source| !source.source_ref.trim().is_empty())
        .map(|source| ContextSource {
            source_ref: source.source_ref.trim().to_owned(),
            label: source.label.trim().to_owned(),
            authority: authority_name(source.authority).to_owned(),
        })
        .collect();

    let mut excluded_sources = Vec::new();
    if input
        .context_sources
        .iter()
        .any(|source| source.source_ref.trim().is_empty())
    {
        excluded_sources.push(ContextNotice {
            code: "CONTEXT_SOURCE_EMPTY".to_owned(),
            detail: "空的上下文来源不会进入工作上下文包".to_owned(),
        });
    }

    let mut required_reads = Vec::new();
    let mut stale_context_warnings = Vec::new();
    let mut confidence = "low";

    if included_sources.is_empty() {
        required_reads.push("project-context".to_owned());
    } else {
        confidence = "source_bound";
        stale_context_warnings.push("上下文来源尚未由 Context Authority 重新验证".to_owned());
    }

    // These fields are carried in the pack as visible preparation facts. The
    // actual Start Gate is evaluated by evaluate_start_gate so it cannot be
    // accidentally bypassed by a renderer or future client surface.
    ContextPack {
        included_sources,
        excluded_sources,
        required_reads,
        stale_context_warnings,
        not_doing: vec![
            "不直接创建或派发 Task".to_owned(),
            "不选择 Provider、Model 或 Harness".to_owned(),
            "不写入永久 Memory".to_owned(),
        ],
        confidence: confidence.to_owned(),
        token_budget: TokenBudget {
            planning_limit: 4_000,
            execution_limit: 0,
        },
    }
}

/// Evaluate the frozen Work-Start Gate from the compiled context pack.
/// Readiness means only that the explicit context prerequisite is present; it
/// never means that a Task is created or dispatch is authorized.
pub fn evaluate_start_gate(context_pack: &ContextPack) -> GateResult {
    let mut blockers = Vec::new();
    if context_pack.included_sources.is_empty() {
        blockers.push(ContextNotice {
            code: "CONTEXT_PACK_EMPTY".to_owned(),
            detail: "至少需要一个明确的项目、Founder 或运行时上下文来源".to_owned(),
        });
    }
    GateResult {
        ready: blockers.is_empty(),
        blockers,
        warnings: if context_pack.included_sources.is_empty() {
            Vec::new()
        } else {
            vec![ContextNotice {
                code: "CONTEXT_EXACT_ONLY".to_owned(),
                detail: "当前预览只使用显式来源，未执行语义检索或模型推断".to_owned(),
            }]
        },
        required_confirmations: vec!["Founder 确认事件包后才允许进入任务创建".to_owned()],
        evidence_required: vec![
            "执行返回必须形成 Artifact/Evidence".to_owned(),
            "最终完成必须经过 Sego 验证与 Founder 裁决".to_owned(),
        ],
        cost_gate_required: true,
    }
}

/// Assemble the event-packet preview after the context and gate stages have
/// completed. This value remains non-dispatchable until a future governance
/// contract records Founder confirmation and creates the authoritative Task.
pub fn build_event_packet(
    work_request: WorkRequest,
    context_pack: ContextPack,
    gate_result: GateResult,
) -> EventPacketPreview {
    let ready_for_founder_confirmation = gate_result.ready;
    EventPacketPreview {
        dispatchable: false,
        work_request,
        context_pack,
        gate_result,
        route: "single_harness (由 Governance Kernel 最终选择)".to_owned(),
        return_format: "Artifact + Evidence + VerificationArtifact + FounderVerdict".to_owned(),
        ready_for_founder_confirmation,
    }
}

/// Build the first Director preview from explicitly supplied context sources.
///
/// The current product baseline deliberately starts with exact/source-aware
/// context. No vector search, model inference, provider routing, or durable
/// state mutation happens here.
pub fn build_event_packet_preview(
    input: &DirectorInput,
) -> Result<EventPacketPreview, DirectorInputError> {
    let work_request = normalize_intent(input)?;
    let context_pack = build_context_pack(input);
    let gate_result = evaluate_start_gate(&context_pack);
    Ok(build_event_packet(work_request, context_pack, gate_result))
}

fn authority_name(authority: ContextAuthority) -> &'static str {
    match authority {
        ContextAuthority::Founder => "founder",
        ContextAuthority::Project => "project",
        ContextAuthority::Runtime => "runtime",
        ContextAuthority::External => "external",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(sources: Vec<ContextSourceInput>) -> DirectorInput {
        DirectorInput {
            intent: "整理 Memory 治理并验证当前实现".to_owned(),
            scope_ref: "project:egopulse".to_owned(),
            work_type: "research_implementation".to_owned(),
            context_sources: sources,
        }
    }

    #[test]
    fn empty_context_is_a_visible_start_gate_blocker() {
        let preview = build_event_packet_preview(&input(Vec::new())).expect("valid input");
        assert!(!preview.dispatchable);
        assert!(!preview.gate_result.ready);
        assert_eq!(preview.gate_result.blockers[0].code, "CONTEXT_PACK_EMPTY");
    }

    #[test]
    fn explicit_context_produces_a_source_bound_preview_without_dispatch() {
        let preview = build_event_packet_preview(&input(vec![ContextSourceInput {
            source_ref: "docs/ARCHITECTURE.md".to_owned(),
            label: "architecture boundary".to_owned(),
            authority: ContextAuthority::Project,
        }]))
        .expect("valid input");
        assert!(!preview.dispatchable);
        assert!(preview.ready_for_founder_confirmation);
        assert!(preview.gate_result.ready);
        assert_eq!(preview.context_pack.confidence, "source_bound");
        assert_eq!(preview.context_pack.token_budget.execution_limit, 0);
        assert!(
            preview
                .context_pack
                .not_doing
                .iter()
                .any(|item| item.contains("Task"))
        );
    }

    #[test]
    fn director_stages_are_composable_and_keep_dispatch_closed() {
        let value = input(vec![ContextSourceInput {
            source_ref: "docs/ARCHITECTURE.md".to_owned(),
            label: "architecture boundary".to_owned(),
            authority: ContextAuthority::Project,
        }]);
        let request = normalize_intent(&value).expect("normalized request");
        let pack = build_context_pack(&value);
        let gate = evaluate_start_gate(&pack);
        let packet = build_event_packet(request.clone(), pack.clone(), gate.clone());

        assert_eq!(packet.work_request, request);
        assert_eq!(packet.context_pack, pack);
        assert_eq!(packet.gate_result, gate);
        assert!(packet.ready_for_founder_confirmation);
        assert!(!packet.dispatchable);
    }

    #[test]
    fn empty_context_source_is_visible_but_never_becomes_an_included_source() {
        let value = input(vec![ContextSourceInput {
            source_ref: "  ".to_owned(),
            label: "empty".to_owned(),
            authority: ContextAuthority::Project,
        }]);
        let pack = build_context_pack(&value);

        assert!(pack.included_sources.is_empty());
        assert_eq!(pack.excluded_sources[0].code, "CONTEXT_SOURCE_EMPTY");
        assert!(!evaluate_start_gate(&pack).ready);
    }

    #[test]
    fn whitespace_is_rejected_before_any_preview_is_built() {
        let mut value = input(Vec::new());
        value.intent = "  ".to_owned();
        assert_eq!(
            normalize_intent(&value),
            Err(DirectorInputError::EmptyIntent)
        );
    }
}
